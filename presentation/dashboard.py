"""
dashboard.py
Main UI for Muhafiz. Run with:
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import sqlite3
import json
from datetime import datetime
from pathlib import Path

from core import run_scan
from analysis.engine import LogicEngine
from analysis.scorer import RiskScorer
from analysis.updater import FingerprintUpdater
from community.sanitizer import Sanitizer
from community.consent import ConsentManager, ContributeMode
from community.client import ContributionClient
from community.history import HistoryTracker
from db.registry import DeviceRegistry # type: ignore

DB_PATH = Path("muhafiz.db")
scorer  = RiskScorer()


st.set_page_config(
    page_title="Muhafiz — Network Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .critical  { color: #E24B4A; font-weight: 600; }
    .high      { color: #D85A30; font-weight: 600; }
    .medium    { color: #BA7517; font-weight: 600; }
    .low       { color: #3B6D11; font-weight: 600; }
    .metric-card {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 1rem;
        text-align: center;
    }
    .new-badge {
        background: #E6F1FB;
        color: #185FA5;
        border-radius: 4px;
        padding: 2px 8px;
        font-size: 11px;
        font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)



with st.sidebar:
    st.image("https://img.shields.io/badge/Muhafiz-ASM-blue", width=150)
    st.title("Muhafiz")
    st.caption("Attack Surface Management")
    st.divider()

    page = st.radio(
        "Navigation",
        ["Dashboard", "Device Registry", "Contributions", "Settings"],
        label_visibility="collapsed"
    )

    st.divider()

    # Fingerprint DB status
    updater = FingerprintUpdater()
    fp_status = updater.status()
    st.caption(f"Fingerprints v{fp_status['version']}")
    st.caption(f"{fp_status['total_signatures']} signatures")

    if not fp_status["api_live"]:
        st.caption("⚪ Community API offline")
    else:
        st.caption("🟢 Community API live")


# ══════════════════════════════════════════════════════════
#  PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════

if page == "Dashboard":

    st.title("Security Scoreboard")
    col1, col2 = st.columns([3, 1])
    with col2:
        run_btn = st.button("Run Scan", type="primary", use_container_width=True)

    if run_btn:
        with st.spinner("Scanning your network..."):
            try:
                result = run_scan()
                engine = LogicEngine()
                result = engine.analyse(result)
                st.session_state["last_result"] = result
                st.session_state["scan_time"]   = datetime.utcnow()

                # Update registry
                registry = DeviceRegistry()
                scan_id  = _save_scan(result) # pyright: ignore[reportUndefinedVariable]
                registry.update(result, scan_id)

                st.success(f"Scan complete — {len(result.devices)} device(s) found")
            except PermissionError:
                st.error("Administrator privileges required. Please restart as admin.")
            except RuntimeError as e:
                st.error(str(e))
    result = st.session_state.get("last_result")

    if result is None:
        st.info("No scan results yet. Click **Run Scan** to start.")
        st.stop()


    m1, m2, m3, m4 = st.columns(4)

    with m1:
        st.metric("Devices found", len(result.devices))
    with m2:
        st.metric("WAN ports exposed", len(result.exposed_ports))
    with m3:
        critical = len([c for c in result.correlations if c.risk_score >= 9])
        st.metric("Critical findings", critical, delta=None)
    with m4:
        avg = sum(c.risk_score for c in result.correlations) / len(result.correlations) \
              if result.correlations else 0
        st.metric("Avg risk score", f"{avg:.1f} / 10")

    st.divider()
    if result.correlations:
        st.subheader("Critical Correlations")
        for corr in result.correlations:
            severity = scorer.label(corr.risk_score)
            color    = severity.lower()

            with st.expander(
                f"[{severity}] {corr.device.ports[0].manufacturer} "
                f"{corr.device.ports[0].device_type} — "
                f"{corr.device.ip} : {corr.exposed_port.port}",
                expanded=corr.risk_score >= 9
            ):
                st.markdown(f"**Risk score:** {corr.risk_score}/10")
                st.markdown(f"**Reason:** {corr.reason}")

                if corr.exposed_port.cves:
                    st.markdown(f"**CVEs:** {', '.join(corr.exposed_port.cves)}")

                # Contribute button
                st.divider()
                _render_contribute_button(corr) # type: ignore

    else:
        st.success("No critical correlations found — your network looks clean.")

    if result.upnp_leaks:
        st.subheader("UPnP Leaks")
        for leak in result.upnp_leaks:
            confirmed = "Confirmed" if leak.lease_duration >= 0 else "Likely"
            st.warning(
                f"**{confirmed} UPnP leak:** {leak.internal_ip}:{leak.internal_port} "
                f"→ external port {leak.external_port}/{leak.protocol} "
                f"— {leak.description}"
            )
    st.subheader("All Devices")
    if result.devices:
        rows = []
        for device in result.devices:
            for port in device.ports:
                rows.append({
                    "IP":           device.ip,
                    "MAC prefix":   ":".join(device.mac.split(":")[:3]) if device.mac else "—",
                    "Hostname":     device.hostname or "—",
                    "Port":         port.port,
                    "Service":      port.service,
                    "Device type":  port.device_type,
                    "Manufacturer": port.manufacturer,
                    "Risk":         scorer.label(
                        scorer.score(port.device_type, port.port in
                                     {ep.port for ep in result.exposed_ports})
                    ),
                })
        st.dataframe(rows, use_container_width=True)
    st.subheader("Shodan — WAN Exposure")
    if result.exposed_ports:
        shodan_rows = []
        for ep in result.exposed_ports:
            shodan_rows.append({
                "Port":     ep.port,
                "Protocol": ep.protocol,
                "Service":  ep.service,
                "CVEs":     ", ".join(ep.cves) if ep.cves else "—",
                "Last seen": ep.last_seen.strftime("%Y-%m-%d") if ep.last_seen else "—",
            })
        st.dataframe(shodan_rows, use_container_width=True)
    else:
        st.info("Shodan has no indexed services for your public IP.")


# ══════════════════════════════════════════════════════════
#  PAGE: DEVICE REGISTRY
# ══════════════════════════════════════════════════════════

elif page == "Device Registry":

    st.title("Exposed Device Registry")
    st.caption("Every device ever found exposed — tracked across scans by MAC prefix.")

    registry = DeviceRegistry()
    stats    = registry.stats()

    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Total exposed",        stats["total_exposed"])
    s2.metric("New since last view",  stats["new_since_last_view"])
    s3.metric("Resolved",             stats["resolved"])
    s4.metric("Highest risk score",   stats["highest_risk_score"])

    st.divider()

    entries = registry.get_all()
    registry.mark_all_viewed()

    if not entries:
        st.info("No exposed devices recorded yet. Run a scan first.")
    else:
        for entry in entries:
            badge = "🆕 " if entry.is_new else ""
            with st.expander(
                f"{badge}{entry.manufacturer} {entry.device_type} "
                f"— {entry.last_ip} (seen {entry.exposure_count}x)",
                expanded=entry.is_new
            ):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**MAC prefix:** `{entry.mac_prefix}`")
                    st.markdown(f"**Last IP:** `{entry.last_ip}`")
                    st.markdown(f"**Hostname:** {entry.hostname or '—'}")
                    st.markdown(f"**Device type:** {entry.device_type}")
                    st.markdown(f"**Manufacturer:** {entry.manufacturer}")
                with c2:
                    st.markdown(f"**Exposed ports:** {entry.exposed_ports}")
                    st.markdown(f"**Highest risk:** {entry.highest_risk_score}/10")
                    st.markdown(f"**First exposed:** {entry.first_exposed.strftime('%Y-%m-%d')}")
                    st.markdown(f"**Last exposed:** {entry.last_exposed.strftime('%Y-%m-%d')}")
                    st.markdown(f"**Times seen:** {entry.exposure_count}")

                # Changelog
                changelog = registry.get_changelog(entry.mac_prefix)
                if changelog:
                    st.markdown("**History:**")
                    for log in changelog:
                        icon = {
                            "first_seen":    "🔴",
                            "new_port":      "🟠",
                            "still_exposed": "🟡",
                            "resolved":      "🟢",
                        }.get(log.event, "⚪")
                        st.caption(
                            f"{icon} {log.recorded_at.strftime('%Y-%m-%d %H:%M')} "
                            f"— {log.detail}"
                        )

                # Resolve button
                if not entry.resolved:
                    if st.button(
                        f"Mark as resolved",
                        key=f"resolve_{entry.mac_prefix}"
                    ):
                        registry.mark_resolved(entry.mac_prefix)
                        st.success("Marked as resolved.")
                        st.rerun()
                else:
                    st.success("Resolved")


# ══════════════════════════════════════════════════════════
#  PAGE: CONTRIBUTIONS
# ══════════════════════════════════════════════════════════

elif page == "Contributions":

    st.title("Community Contributions")
    st.caption(
        "Contributions are anonymous — no IPs or MAC addresses are ever sent. "
        "Local history is yours to manage. "
        "**Note:** clearing history does not remove submitted signatures "
        "from the community database."
    )

    history = HistoryTracker()
    stats   = history.stats()

    h1, h2, h3, h4 = st.columns(4)
    h1.metric("Total contributed", stats["total"])
    h2.metric("Merged",            stats["merged"])
    h3.metric("Pending",           stats["pending"])
    h4.metric("Queued (offline)",  stats["queued"])

    st.divider()

  
    entries = history.get_all()
    if not entries:
        st.info("No contributions yet.")
    else:
        rows = []
        for e in entries:
            rows.append({
                "Date":         e.contributed_at.strftime("%Y-%m-%d"),
                "Port":         e.port,
                "Device":       f"{e.manufacturer} {e.device_type}",
                "Banner":       e.banner_snippet[:40] + "..." if len(e.banner_snippet) > 40 else e.banner_snippet,
                "Risk":         e.risk_score,
                "Shodan match": "Yes" if e.shodan_match else "No",
                "Status":       e.status.upper(),
            })
        st.dataframe(rows, use_container_width=True)

    st.divider()

    st.subheader("Manage history")
    st.warning(
        "Clearing local history only removes records from this device. "
        "It does NOT remove any signatures already submitted to "
        "the community database — those are permanent once merged."
    )
    if st.button("Clear local history", type="secondary"):
        history.clear_all()
        st.success("Local contribution history cleared.")
        st.rerun()


# ══════════════════════════════════════════════════════════
#  PAGE: SETTINGS
# ══════════════════════════════════════════════════════════

elif page == "Settings":

    st.title("Settings")

    consent = ConsentManager()
    summary = consent.summary()

    st.subheader("Contribution preferences")

    mode = st.selectbox(
        "Contribution mode",
        options=["ask", "auto", "never"],
        index=["ask", "auto", "never"].index(summary["mode"]),
        help="ask = prompt each time | auto = contribute automatically above threshold | never = opt out"
    )

    threshold = st.slider(
        "Auto-contribute threshold (risk score)",
        min_value=1,
        max_value=10,
        value=summary["auto_threshold"] or 8,
        disabled=(mode != "auto"),
        help="Only auto-contribute findings at or above this risk score."
    )

    if st.button("Save preferences"):
        consent.set_mode(ContributeMode(mode))
        if mode == "auto":
            consent.set_auto_threshold(threshold)
        st.success("Preferences saved.")

    st.divider()
    st.subheader("Fingerprint database")

    updater   = FingerprintUpdater()
    fp_status = updater.status()

    st.markdown(f"**Version:** {fp_status['version']}")
    st.markdown(f"**Total signatures:** {fp_status['total_signatures']}")
    st.markdown(f"**Last updated:** {fp_status['updated_at']}")

    if st.button("Check for updates now"):
        with st.spinner("Checking..."):
            updated = updater.check_and_update()
        if updated:
            st.success("Fingerprints updated to latest version.")
        else:
            st.info("Already up to date.")


#helper fnctions

def _render_contribute_button(corr):
    """Show the contribute button and consent dialog for a finding."""
    sanitizer = Sanitizer()
    preview   = sanitizer.preview(corr)

    with st.expander("Contribute this finding to the community database"):
        st.markdown("**What will be sent:**")
        st.json(preview["will_send"])

        st.markdown("**What will be stripped (never sent):**")
        st.json(preview["will_strip"])

        c1, c2, c3 = st.columns(3)
        with c1:
            agree1 = st.checkbox(
                "I understand only the data above will be sent.",
                key=f"agree1_{corr.device.ip}_{corr.exposed_port.port}"
            )
        with c2:
            agree2 = st.checkbox(
                "I consent to anonymous data being stored in the community DB.",
                key=f"agree2_{corr.device.ip}_{corr.exposed_port.port}"
            )
        with c3:
            agree3 = st.checkbox(
                "I understand contributions are public.",
                key=f"agree3_{corr.device.ip}_{corr.exposed_port.port}"
            )

        if st.button(
            "Submit contribution",
            disabled=not (agree1 and agree2 and agree3),
            key=f"submit_{corr.device.ip}_{corr.exposed_port.port}"
        ):
            try:
                payload = sanitizer.build_payload(corr)
                valid, reason = sanitizer.validate(payload)
                if not valid:
                    st.error(f"Validation failed: {reason}")
                    return

                client = ContributionClient()
                result = client.submit(payload)

                consent = ConsentManager()
                consent.record_consent(corr.exposed_port.port, approved=True)

                st.success(
                    f"Submitted — status: {result['status']}. "
                    f"UUID: {result['uuid'][:8]}..."
                )
            except Exception as e:
                st.error(f"Submission failed: {e}")


def _save_scan(result) -> int:
    """Save a ScanResult summary to the local DB and return the scan_id."""
    import hashlib
    wan_hash = hashlib.sha256(result.wan_ip.encode()).hexdigest()
    avg_risk = (
        sum(c.risk_score for c in result.correlations) / len(result.correlations)
        if result.correlations else 0.0
    )
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (wan_ip_hash, subnet, device_count, exposed_port_count,
             correlation_count, upnp_leak_count, risk_score_avg)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            wan_hash,
            result.subnet,
            len(result.devices),
            len(result.exposed_ports),
            len(result.correlations),
            len(result.upnp_leaks),
            avg_risk,
        ))
        conn.commit()
        return cursor.lastrowid