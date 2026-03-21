"""
dashboard.py
Presentation Layer — Muhafiz Security Scoreboard
Full LAN architecture: Exposure findings + Device findings + Confidence scores.
Run with:
    streamlit run presentation/dashboard.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path

import streamlit as st

from core import run_scan
from core.models import ExposureFinding, DeviceRiskFinding
from analysis.scorer import RiskScorer
from analysis.updater import FingerprintUpdater
from community.sanitizer import Sanitizer
from community.consent import ConsentManager, ContributeMode
from community.client import ContributionClient
from community.history import HistoryTracker
from db.registry import DeviceRegistry

DB_PATH = Path("muhafiz.db")
scorer  = RiskScorer()

# ── Severity colours ───────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": "#E24B4A",
    "HIGH":     "#D85A30",
    "MEDIUM":   "#BA7517",
    "LOW":      "#3B6D11",
}

# ── Page config ────────────────────────────────────────────
st.set_page_config(
    page_title="Muhafiz — LAN Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .critical { color: #E24B4A; font-weight: 600; }
    .high     { color: #D85A30; font-weight: 600; }
    .medium   { color: #BA7517; font-weight: 600; }
    .low      { color: #3B6D11; font-weight: 600; }
    .conf-tag {
        font-size: 11px; padding: 2px 8px;
        border-radius: 4px; font-weight: 500;
    }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ────────────────────────────────────────────────
with st.sidebar:
    st.title("Muhafiz")
    st.caption("LAN Security Scanner")
    st.divider()

    page = st.radio(
        "Navigation",
        ["Dashboard", "Device Registry", "Contributions", "Settings"],
        label_visibility="collapsed"
    )

    st.divider()
    fp   = FingerprintUpdater().status()
    st.caption(f"Fingerprints v{fp['version']} · {fp['total_signatures']} sigs")


# ══════════════════════════════════════════════════════════
#  PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════

if page == "Dashboard":

    st.title("Security Scoreboard")

    col1, col2 = st.columns([3, 1])
    with col2:
        run_btn = st.button(
            "Run Scan", type="primary", use_container_width=True
        )

    if run_btn:
        with st.spinner("Scanning your network..."):
            try:
                result = run_scan()
                st.session_state["last_result"] = result
                st.session_state["scan_time"]   = datetime.utcnow()

                scan_id = _save_scan(result)
                DeviceRegistry().update(result, scan_id)

                st.success(
                    f"Scan complete — "
                    f"{len(result.devices)} device(s), "
                    f"{len(result.exposure_findings)} exposure finding(s), "
                    f"{len(result.device_findings)} internal finding(s)"
                )
            except PermissionError:
                st.error(
                    "Administrator privileges required. "
                    "Please restart terminal as admin and run again."
                )
            except Exception as e:
                st.error(f"Scan error: {e}")

    result = st.session_state.get("last_result")

    if result is None:
        st.info("No scan results yet. Click **Run Scan** to start.")
        st.stop()

    # ── Metric cards ───────────────────────────────────────
    m1, m2, m3, m4, m5 = st.columns(5)

    confirmed = len([
        f for f in result.exposure_findings if f.confidence == 100
    ])
    critical_exp = len([
        f for f in result.exposure_findings if f.severity == "CRITICAL"
    ])
    critical_dev = len([
        f for f in result.device_findings if f.severity == "CRITICAL"
    ])

    m1.metric("Devices found",        len(result.devices))
    m2.metric("Router mappings",       len(result.mappings))
    m3.metric("Exposure findings",     len(result.exposure_findings))
    m4.metric("Confirmed reachable",   confirmed)
    m5.metric("Internal risk devices", len(result.device_findings))

    # CGNAT warning
    if result.wan_ip:
        parts = result.wan_ip.split(".")
        try:
            if int(parts[0]) == 100 and 64 <= int(parts[1]) <= 127:
                st.warning(
                    "CGNAT detected — your ISP uses shared NAT. "
                    "Direct external exposure is unlikely but port "
                    "mappings should still be removed."
                )
        except Exception:
            pass

    st.divider()

    # ── Exposure findings ──────────────────────────────────
    if result.exposure_findings:
        st.subheader("Exposure Findings")
        st.caption(
            "These devices have confirmed router port mappings. "
            "Confidence 100% = externally verified reachable."
        )

        for finding in result.exposure_findings:
            conf_label  = RiskScorer.confidence_label(finding.confidence)
            conf_color  = {
                "Confirmed":  "#E24B4A",
                "Likely":     "#D85A30",
                "Possible":   "#BA7517",
                "Uncertain":  "#888780",
            }.get(conf_label, "#888780")

            header = (
                f"[{finding.severity}] "
                f"{finding.device.ports[0].manufacturer if finding.device.ports else 'Unknown'} "
                f"{finding.device.ports[0].device_type if finding.device.ports else ''} "
                f"— {finding.device.ip} "
                f"| Score {finding.risk_score}/10 "
                f"| {conf_label} ({finding.confidence}%)"
            )

            with st.expander(
                header,
                expanded=finding.severity in ("CRITICAL", "HIGH")
            ):
                c1, c2 = st.columns(2)

                with c1:
                    st.markdown("**Device**")
                    st.markdown(f"IP: `{finding.device.ip}`")
                    st.markdown(
                        f"MAC prefix: `"
                        f"{':'.join(finding.device.mac.split(':')[:3]) if finding.device.mac else '—'}`"
                    )
                    st.markdown(f"Hostname: {finding.device.hostname or '—'}")
                    if finding.device.is_camera:
                        st.markdown("**ONVIF camera confirmed**")
                        if finding.device.onvif_info.get("model"):
                            st.markdown(
                                f"Model: {finding.device.onvif_info['model']}"
                            )

                with c2:
                    st.markdown("**Router mapping**")
                    st.markdown(
                        f"External port: `{finding.mapping.external_port}`"
                    )
                    st.markdown(
                        f"Internal: `{finding.mapping.internal_ip}:"
                        f"{finding.mapping.internal_port}`"
                    )
                    st.markdown(f"Source: `{finding.mapping.source}`")
                    st.markdown(f"Protocol: `{finding.mapping.protocol}`")

                    if finding.verification:
                        st.markdown("**External verification**")
                        if finding.verification.reachable:
                            st.error(
                                f"Reachable from internet via "
                                f"{finding.verification.protocol.upper()}"
                            )
                            if finding.verification.banner:
                                st.code(
                                    finding.verification.banner[:200],
                                    language=None
                                )
                        else:
                            st.warning(
                                "Mapping confirmed but external connection failed "
                                "(firewall or CGNAT). Mapping should still be removed."
                            )

                st.markdown("**Why this score:**")
                for reason in finding.reasons:
                    st.caption(f"• {reason}")

                st.markdown("**How to fix:**")
                for step in finding.remediation:
                    st.caption(f"→ {step}")

                st.divider()
                _render_contribute_button(finding)

    else:
        st.success(
            "No confirmed router mappings found — "
            "no devices are exposed via UPnP or port forwarding."
        )

    # ── UPnP leaks ─────────────────────────────────────────
    if result.upnp_leaks:
        st.subheader("UPnP Port Mappings")
        for leak in result.upnp_leaks:
            st.warning(
                f"**{leak.source.upper()}** mapping: "
                f"`{leak.internal_ip}:{leak.internal_port}` → "
                f"external port `{leak.external_port}/{leak.protocol}` "
                f"— {leak.description}"
            )

    # ── Internal risk findings ─────────────────────────────
    if result.device_findings:
        st.subheader("Internal Risk Devices")
        st.caption(
            "No confirmed port mappings — internal risk only. "
            "These devices are not currently exposed externally."
        )

        # Only show MEDIUM and above
        show = [f for f in result.device_findings if f.risk_score >= 5]
        if show:
            for finding in show:
                with st.expander(
                    f"[{finding.severity}] "
                    f"{finding.device.ports[0].manufacturer if finding.device.ports else 'Unknown'} "
                    f"{finding.device.ports[0].device_type if finding.device.ports else ''} "
                    f"— {finding.device.ip} "
                    f"| Score {finding.risk_score}/10 "
                    f"| {RiskScorer.confidence_label(finding.confidence)}",
                    expanded=False
                ):
                    st.markdown(f"**IP:** `{finding.device.ip}`")
                    st.markdown(
                        f"**Open ports:** "
                        f"{[p.port for p in finding.device.ports]}"
                    )
                    st.markdown("**Reasons:**")
                    for r in finding.reasons:
                        st.caption(f"• {r}")
                    st.markdown("**Remediation:**")
                    for s in finding.remediation:
                        st.caption(f"→ {s}")
        else:
            st.info("No medium or high risk internal devices.")

    # ── All devices table ──────────────────────────────────
    st.subheader("All Devices")
    if result.devices:
        rows = []
        for d in result.devices:
            dtype = "ip_camera" if d.is_camera else (
                d.ports[0].device_type if d.ports else "unknown"
            )
            mfr = (
                d.onvif_info.get("manufacturer") or
                (d.ports[0].manufacturer if d.ports else "unknown")
            )
            has_mapping = any(
                f.device.ip == d.ip for f in result.exposure_findings
            )
            rows.append({
                "IP":           d.ip,
                "MAC prefix":   ":".join(d.mac.split(":")[:3]) if d.mac else "—",
                "Hostname":     d.hostname or "—",
                "Type":         dtype,
                "Manufacturer": mfr,
                "Camera":       "Yes" if d.is_camera else "No",
                "Ports":        ", ".join(str(p.port) for p in d.ports[:6]),
                "Mapping":      "Yes" if has_mapping else "No",
            })
        st.dataframe(rows, use_container_width=True)


# ══════════════════════════════════════════════════════════
#  PAGE: DEVICE REGISTRY
# ══════════════════════════════════════════════════════════

elif page == "Device Registry":

    st.title("Device Registry")
    st.caption(
        "Every device seen across scans — tracked by MAC prefix. "
        "Exposure count = number of scans with a confirmed router mapping."
    )

    registry = DeviceRegistry()
    stats    = registry.stats()
    registry.mark_all_viewed()

    # Stats row
    s1, s2, s3, s4, s5, s6 = st.columns(6)
    s1.metric("Total devices",     stats["total"])
    s2.metric("New since view",    stats["new_since_view"])
    s3.metric("Ever exposed",      stats["ever_exposed"])
    s4.metric("Cameras",           stats["cameras"])
    s5.metric("Confirmed reach.",  stats["confirmed_reachable"])
    s6.metric("Resolved",          stats["resolved"])

    st.divider()

    tab1, tab2 = st.tabs(["All devices", "Ever exposed"])

    with tab1:
        entries = registry.get_all()
        _render_registry_entries(entries, registry)

    with tab2:
        entries = registry.get_exposed()
        if not entries:
            st.info("No devices have had confirmed router mappings yet.")
        else:
            _render_registry_entries(entries, registry)


# ══════════════════════════════════════════════════════════
#  PAGE: CONTRIBUTIONS
# ══════════════════════════════════════════════════════════

elif page == "Contributions":

    st.title("Community Contributions")
    st.caption(
        "Contributions are anonymous — no IPs, MACs, or mapping details "
        "are ever sent. Clearing local history does **not** remove submitted "
        "signatures from the community database."
    )

    history = HistoryTracker()
    stats   = history.stats()

    h1, h2, h3, h4 = st.columns(4)
    h1.metric("Total contributed", stats["total"])
    h2.metric("Merged",            stats["merged"])
    h3.metric("Pending",           stats["pending"])
    h4.metric("Queued offline",    stats["queued"])

    st.divider()

    entries = history.get_all()
    if not entries:
        st.info("No contributions yet.")
    else:
        rows = []
        for e in entries:
            rows.append({
                "Date":     e.contributed_at.strftime("%Y-%m-%d"),
                "Port":     e.port,
                "Device":   f"{e.manufacturer} {e.device_type}",
                "Banner":   (
                    e.banner_snippet[:40] + "..."
                    if len(e.banner_snippet) > 40
                    else e.banner_snippet
                ),
                "Risk":     e.risk_score,
                "Status":   e.status.upper(),
            })
        st.dataframe(rows, use_container_width=True)

    st.divider()
    st.subheader("Manage history")
    st.warning(
        "This removes local records only. "
        "Submitted signatures stay in the community database permanently."
    )
    if st.button("Clear local history", type="secondary"):
        history.clear_all()
        st.success("Local history cleared.")
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
        help=(
            "ask = prompt each time | "
            "auto = contribute automatically | "
            "never = opt out"
        )
    )
    threshold = st.slider(
        "Auto-contribute threshold (risk score)",
        min_value=1, max_value=10,
        value=summary["auto_threshold"] or 8,
        disabled=(mode != "auto"),
    )
    if st.button("Save preferences"):
        consent.set_mode(ContributeMode(mode))
        if mode == "auto":
            consent.set_auto_threshold(threshold)
        st.success("Preferences saved.")

    st.divider()
    st.subheader("Fingerprint database")
    fp = FingerprintUpdater()
    s  = fp.status()
    st.markdown(f"**Version:** {s['version']}")
    st.markdown(f"**Signatures:** {s['total_signatures']}")
    st.markdown(f"**Last updated:** {s['updated_at']}")
    if st.button("Check for updates"):
        with st.spinner("Checking..."):
            updated = fp.check_and_update()
        st.success("Updated." if updated else "Already up to date.")


def _render_registry_entries(entries, registry):
    if not entries:
        st.info("No devices recorded yet.")
        return
    for entry in entries:
        badge = "🆕 " if entry.is_new else ""
        cam   = "📷 " if entry.is_camera else ""
        with st.expander(
            f"{badge}{cam}{entry.manufacturer} {entry.device_type} "
            f"— {entry.last_ip} "
            f"| Risk {entry.highest_risk_score}/10 "
            f"| Seen {entry.scan_count}x "
            f"| Exposed {entry.exposure_count}x",
            expanded=entry.is_new
        ):
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"**MAC prefix:** `{entry.mac_prefix}`")
                st.markdown(f"**Last IP:** `{entry.last_ip}`")
                st.markdown(f"**Hostname:** {entry.hostname or '—'}")
                st.markdown(f"**Type:** {entry.device_type}")
                st.markdown(f"**Manufacturer:** {entry.manufacturer}")
                st.markdown(f"**Camera:** {'Yes' if entry.is_camera else 'No'}")
            with c2:
                st.markdown(f"**Open ports:** {entry.open_ports}")
                st.markdown(f"**Highest risk:** {entry.highest_risk_score}/10")
                st.markdown(
                    f"**Highest confidence:** {entry.highest_confidence}% "
                    f"({RiskScorer.confidence_label(entry.highest_confidence)})"
                )
                st.markdown(f"**Times seen:** {entry.scan_count}")
                st.markdown(f"**Times exposed:** {entry.exposure_count}")
                st.markdown(
                    f"**First seen:** {entry.first_seen.strftime('%Y-%m-%d')}"
                )
                st.markdown(
                    f"**Last seen:** {entry.last_seen.strftime('%Y-%m-%d')}"
                )

            changelog = registry.get_changelog(entry.mac_prefix, limit=10)
            if changelog:
                st.markdown("**History:**")
                icons = {
                    "first_seen":         "🔵",
                    "first_seen_exposed": "🔴",
                    "now_exposed":        "🟠",
                    "new_port":           "🟡",
                    "still_present":      "⚪",
                    "resolved":           "🟢",
                }
                for log in changelog:
                    icon = icons.get(log.event, "⚪")
                    st.caption(
                        f"{icon} {log.recorded_at.strftime('%Y-%m-%d %H:%M')} "
                        f"— {log.detail} "
                        f"(risk {log.risk_score}, conf {log.confidence}%)"
                    )

            if not entry.resolved:
                if st.button(
                    "Mark as resolved",
                    key=f"resolve_{entry.mac_prefix}"
                ):
                    registry.mark_resolved(entry.mac_prefix)
                    st.success("Marked as resolved.")
                    st.rerun()
            else:
                st.success("Resolved")


def _render_contribute_button(finding):
    sanitizer = Sanitizer()
    preview   = sanitizer.preview(finding)

    with st.expander("Contribute this finding to the community database"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Will be sent (anonymous):**")
            st.json(preview["will_send"])
        with col2:
            st.markdown("**Will be stripped (never sent):**")
            st.json(preview["will_strip"])

        a1 = st.checkbox(
            "Only the data above will be sent — no IPs or identifiers.",
            key=f"a1_{finding.device.ip}_{finding.risk_score}"
        )
        a2 = st.checkbox(
            "I consent to this anonymous data being stored in the community DB.",
            key=f"a2_{finding.device.ip}_{finding.risk_score}"
        )
        a3 = st.checkbox(
            "I understand contributions are public and permanent.",
            key=f"a3_{finding.device.ip}_{finding.risk_score}"
        )

        if st.button(
            "Submit contribution",
            disabled=not (a1 and a2 and a3),
            key=f"submit_{finding.device.ip}_{finding.risk_score}"
        ):
            try:
                payload        = sanitizer.build_payload(finding)
                valid, reason  = sanitizer.validate(payload)
                if not valid:
                    st.error(f"Validation failed: {reason}")
                    return
                client = ContributionClient()
                res    = client.submit(payload)
                ConsentManager().record_consent(
                    finding.device.ports[0].port if finding.device.ports else 0,
                    True
                )
                st.success(
                    f"Submitted — status: {res['status']}. "
                    f"UUID: {res['uuid'][:8]}..."
                )
            except Exception as e:
                st.error(f"Submission failed: {e}")


def _save_scan(result) -> int:
    confirmed = len([f for f in result.exposure_findings if f.confidence == 100])
    wan_partial = ""
    if result.wan_ip:
        parts = result.wan_ip.split(".")
        wan_partial = f"{parts[0]}.x.x.x" if len(parts) == 4 else ""

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id                     INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp              TEXT NOT NULL DEFAULT (datetime('now')),
                subnet                 TEXT NOT NULL,
                wan_ip_partial         TEXT NOT NULL DEFAULT '',
                device_count           INTEGER NOT NULL DEFAULT 0,
                mapping_count          INTEGER NOT NULL DEFAULT 0,
                exposure_finding_count INTEGER NOT NULL DEFAULT 0,
                device_finding_count   INTEGER NOT NULL DEFAULT 0,
                upnp_leak_count        INTEGER NOT NULL DEFAULT 0,
                confirmed_reachable    INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor = conn.execute("""
            INSERT INTO scans
            (subnet, wan_ip_partial, device_count, mapping_count,
             exposure_finding_count, device_finding_count,
             upnp_leak_count, confirmed_reachable)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.subnet,
            wan_partial,
            len(result.devices),
            len(result.mappings),
            len(result.exposure_findings),
            len(result.device_findings),
            len(result.upnp_leaks),
            confirmed,
        ))
        conn.commit()
        return cursor.lastrowid