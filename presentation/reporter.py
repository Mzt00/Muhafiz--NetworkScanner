"""
reporter.py
Generates a professional security report from a ScanResult.
Uses ReportLab for PDF generation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.platypus.flowables import KeepTogether

from core.models import ScanResult
from analysis.scorer import RiskScorer

scorer = RiskScorer()
RED       = colors.HexColor("#E24B4A")
ORANGE    = colors.HexColor("#D85A30")
AMBER     = colors.HexColor("#BA7517")
GREEN     = colors.HexColor("#3B6D11")
BLUE      = colors.HexColor("#185FA5")
DARK      = colors.HexColor("#1a1a1a")
LIGHT_BG  = colors.HexColor("#f8f9fa")
BORDER    = colors.HexColor("#dee2e6")

SEVERITY_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   AMBER,
    "LOW":      GREEN,
}


class ReportGenerator:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._build_styles()

    def _build_styles(self):
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            fontSize=28, fontName="Helvetica-Bold",
            textColor=DARK, alignment=TA_LEFT,
            spaceAfter=6,
        ))
        self.styles.add(ParagraphStyle(
            name="ReportSubtitle",
            fontSize=12, fontName="Helvetica",
            textColor=colors.HexColor("#6c757d"),
            spaceAfter=20,
        ))
        self.styles.add(ParagraphStyle(
            name="SectionHeader",
            fontSize=14, fontName="Helvetica-Bold",
            textColor=DARK, spaceBefore=16, spaceAfter=8,
            borderPadding=(0, 0, 4, 0),
        ))
        self.styles.add(ParagraphStyle(
            name="Body",
            fontSize=10, fontName="Helvetica",
            textColor=DARK, spaceAfter=6, leading=14,
        ))
        self.styles.add(ParagraphStyle(
            name="Caption",
            fontSize=8, fontName="Helvetica",
            textColor=colors.HexColor("#6c757d"),
            spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name="Code",
            fontSize=8, fontName="Courier",
            textColor=DARK, backColor=LIGHT_BG,
            spaceAfter=4, leftIndent=8,
        ))
        self.styles.add(ParagraphStyle(
            name="AlertTitle",
            fontSize=11, fontName="Helvetica-Bold",
            textColor=DARK, spaceAfter=4,
        ))

    def generate(self, result: ScanResult, output_path: str = None) -> str:
        """
        Generate a PDF security report from a ScanResult.
        Returns the path to the generated PDF file.
        """
        if output_path is None:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            output_path = f"reports/muhafiz_report_{ts}.pdf"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )

        story = []
        story += self._build_cover(result)
        story += self._build_executive_summary(result)
        story += self._build_critical_findings(result)
        story += self._build_upnp_section(result)
        story += self._build_device_inventory(result)
        story += self._build_shodan_section(result)
        story += self._build_google_dorks(result)
        story += self._build_remediation(result)

        doc.build(
            story,
            onFirstPage=self._header_footer,
            onLaterPages=self._header_footer,
        )

        return output_path


    def _build_cover(self, result: ScanResult) -> list:
        elements = []
        elements.append(Spacer(1, 3*cm))

        elements.append(Paragraph("MUHAFIZ", ParagraphStyle(
            name="CoverTitle", fontSize=48, fontName="Helvetica-Bold",
            textColor=BLUE, alignment=TA_CENTER,
        )))
        elements.append(Paragraph("Network Security Report", ParagraphStyle(
            name="CoverSub", fontSize=18, fontName="Helvetica",
            textColor=DARK, alignment=TA_CENTER, spaceAfter=4,
        )))

        elements.append(Spacer(1, 1*cm))
        elements.append(HRFlowable(width="100%", thickness=1, color=BORDER))
        elements.append(Spacer(1, 1*cm))

        # Summary table on cover
        correlations  = result.correlations
        critical_count = len([c for c in correlations if c.risk_score >= 9])
        avg_risk = (
            sum(c.risk_score for c in correlations) / len(correlations)
            if correlations else 0
        )

        cover_data = [
            ["Scan date",       result.timestamp.strftime("%B %d, %Y at %H:%M UTC")],
            ["Subnet scanned",  result.subnet],
            ["Devices found",   str(len(result.devices))],
            ["WAN ports exposed", str(len(result.exposed_ports))],
            ["Critical findings", str(critical_count)],
            ["Overall risk score", f"{avg_risk:.1f} / 10"],
        ]

        cover_table = Table(cover_data, colWidths=[6*cm, 10*cm])
        cover_table.setStyle(TableStyle([
            ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",    (1,0), (1,-1), "Helvetica"),
            ("FONTSIZE",    (0,0), (-1,-1), 11),
            ("TEXTCOLOR",   (0,0), (0,-1), colors.HexColor("#6c757d")),
            ("TEXTCOLOR",   (1,0), (1,-1), DARK),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, LIGHT_BG]),
            ("TOPPADDING",  (0,0), (-1,-1), 8),
            ("BOTTOMPADDING",(0,0),(-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 12),
        ]))

        elements.append(cover_table)
        elements.append(Spacer(1, 2*cm))

        # Overall severity badge
        if avg_risk >= 9:
            badge_color, badge_text = RED, "CRITICAL RISK"
        elif avg_risk >= 7:
            badge_color, badge_text = ORANGE, "HIGH RISK"
        elif avg_risk >= 5:
            badge_color, badge_text = AMBER, "MEDIUM RISK"
        else:
            badge_color, badge_text = GREEN, "LOW RISK"

        badge_table = Table([[badge_text]], colWidths=[16*cm])
        badge_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,-1), badge_color),
            ("TEXTCOLOR",    (0,0), (-1,-1), colors.white),
            ("FONTNAME",     (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 16),
            ("ALIGN",        (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING",   (0,0), (-1,-1), 12),
            ("BOTTOMPADDING",(0,0), (-1,-1), 12),
            ("ROUNDEDCORNERS", [4]),
        ]))
        elements.append(badge_table)
        elements.append(PageBreak())
        return elements



    def _build_executive_summary(self, result: ScanResult) -> list:
        elements = []
        elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        critical = [c for c in result.correlations if c.risk_score >= 9]
        high     = [c for c in result.correlations if 7 <= c.risk_score < 9]
        medium   = [c for c in result.correlations if 5 <= c.risk_score < 7]
        low      = [c for c in result.correlations if c.risk_score < 5]

        summary_text = (
            f"This report was generated by Muhafiz on "
            f"{result.timestamp.strftime('%B %d, %Y')}. "
            f"A total of <b>{len(result.devices)}</b> devices were discovered on "
            f"subnet <b>{result.subnet}</b>. "
            f"Shodan returned <b>{len(result.exposed_ports)}</b> port(s) "
            f"indexed on your public IP address. "
            f"Cross-referencing internal devices with external exposure identified "
            f"<b>{len(result.correlations)}</b> critical correlation(s): "
            f"{len(critical)} CRITICAL, {len(high)} HIGH, "
            f"{len(medium)} MEDIUM, {len(low)} LOW. "
        )

        if result.upnp_leaks:
            summary_text += (
                f"Additionally, <b>{len(result.upnp_leaks)}</b> UPnP port mapping(s) "
                f"were detected that may be exposing internal devices to the internet."
            )

        elements.append(Paragraph(summary_text, self.styles["Body"]))
        elements.append(Spacer(1, 0.5*cm))

        # Severity breakdown table
        sev_data = [
            ["Severity", "Count", "Description"],
            ["CRITICAL", str(len(critical)), "Immediate action required"],
            ["HIGH",     str(len(high)),     "Address within 24 hours"],
            ["MEDIUM",   str(len(medium)),   "Address within 1 week"],
            ["LOW",      str(len(low)),      "Address when possible"],
        ]

        sev_table = Table(sev_data, colWidths=[4*cm, 3*cm, 9*cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 9),
            ("ALIGN",        (0,0), (-1,-1), "LEFT"),
            ("TOPPADDING",   (0,0), (-1,-1), 7),
            ("BOTTOMPADDING",(0,0), (-1,-1), 7),
            ("LEFTPADDING",  (0,0), (-1,-1), 10),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [colors.white, LIGHT_BG]),
            ("GRID",         (0,0), (-1,-1), 0.5, BORDER),
            # Colour severity cells
            ("TEXTCOLOR",    (0,1), (0,1), RED),
            ("TEXTCOLOR",    (0,2), (0,2), ORANGE),
            ("TEXTCOLOR",    (0,3), (0,3), AMBER),
            ("TEXTCOLOR",    (0,4), (0,4), GREEN),
            ("FONTNAME",     (0,1), (0,-1), "Helvetica-Bold"),
        ]))

        elements.append(sev_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements



    def _build_critical_findings(self, result: ScanResult) -> list:
        elements = []

        if not result.correlations:
            return elements

        elements.append(Paragraph("Critical Findings", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        for i, corr in enumerate(result.correlations, 1):
            severity    = scorer.label(corr.risk_score)
            sev_color   = SEVERITY_COLORS.get(severity, DARK)
            open_port   = corr.device.ports[0] if corr.device.ports else None

            finding_elements = []

            # Finding header
            header_data = [[
                f"Finding #{i}  —  {severity}  —  Risk {corr.risk_score}/10",
                f"{open_port.manufacturer if open_port else 'Unknown'} "
                f"{open_port.device_type if open_port else ''}"
            ]]
            header_table = Table(header_data, colWidths=[10*cm, 6*cm])
            header_table.setStyle(TableStyle([
                ("BACKGROUND",   (0,0), (-1,-1), sev_color),
                ("TEXTCOLOR",    (0,0), (-1,-1), colors.white),
                ("FONTNAME",     (0,0), (-1,-1), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 10),
                ("TOPPADDING",   (0,0), (-1,-1), 8),
                ("BOTTOMPADDING",(0,0), (-1,-1), 8),
                ("LEFTPADDING",  (0,0), (-1,-1), 10),
                ("RIGHTPADDING", (0,0), (-1,-1), 10),
            ]))
            finding_elements.append(header_table)

            # Details table
            details = [
                ["Internal IP",    corr.device.ip],
                ["MAC prefix",     ":".join(corr.device.mac.split(":")[:3]) if corr.device.mac else "—"],
                ["Hostname",       corr.device.hostname or "—"],
                ["Exposed port",   f"{corr.exposed_port.port}/{corr.exposed_port.protocol}"],
                ["Service",        corr.exposed_port.service or "—"],
                ["CVEs",           ", ".join(corr.exposed_port.cves) if corr.exposed_port.cves else "None"],
            ]
            details_table = Table(details, colWidths=[4*cm, 12*cm])
            details_table.setStyle(TableStyle([
                ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",     (0,0), (-1,-1), 9),
                ("TEXTCOLOR",    (0,0), (0,-1), colors.HexColor("#6c757d")),
                ("TEXTCOLOR",    (1,0), (1,-1), DARK),
                ("ROWBACKGROUNDS",(0,0),(-1,-1),[colors.white, LIGHT_BG]),
                ("TOPPADDING",   (0,0), (-1,-1), 5),
                ("BOTTOMPADDING",(0,0), (-1,-1), 5),
                ("LEFTPADDING",  (0,0), (-1,-1), 10),
                ("GRID",         (0,0), (-1,-1), 0.3, BORDER),
            ]))
            finding_elements.append(details_table)

            # Reason
            finding_elements.append(Spacer(1, 0.2*cm))
            finding_elements.append(Paragraph(
                f"<b>Analysis:</b> {corr.reason}",
                self.styles["Body"]
            ))

            elements.append(KeepTogether(finding_elements))
            elements.append(Spacer(1, 0.5*cm))

        return elements

    def _build_upnp_section(self, result: ScanResult) -> list:
        elements = []

        if not result.upnp_leaks:
            return elements

        elements.append(Paragraph("UPnP Leaks", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        elements.append(Paragraph(
            "The following UPnP port mappings were detected on your router. "
            "These allow internal devices to punch holes through your firewall "
            "automatically, potentially exposing them to the internet without "
            "your knowledge.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 0.3*cm))

        upnp_data = [["Internal IP", "Int. Port", "Ext. Port", "Protocol", "Description", "Confirmed"]]
        for leak in result.upnp_leaks:
            upnp_data.append([
                leak.internal_ip,
                str(leak.internal_port),
                str(leak.external_port),
                leak.protocol,
                leak.description[:40] + "..." if len(leak.description) > 40 else leak.description,
                "Yes" if leak.lease_duration >= 0 else "Likely",
            ])

        upnp_table = Table(upnp_data, colWidths=[3.5*cm, 2*cm, 2*cm, 2*cm, 5*cm, 2*cm])
        upnp_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT_BG]),
            ("GRID",         (0,0), (-1,-1), 0.3, BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        elements.append(upnp_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements

    # ── Device inventory ───────────────────────────────────

    def _build_device_inventory(self, result: ScanResult) -> list:
        elements = []
        elements.append(Paragraph("Device Inventory", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        inv_data = [["IP", "MAC prefix", "Hostname", "Type", "Manufacturer", "Open ports"]]
        for device in result.devices:
            mac_prefix = ":".join(device.mac.split(":")[:3]) if device.mac else "—"
            ports_str  = ", ".join(str(p.port) for p in device.ports[:5])
            if len(device.ports) > 5:
                ports_str += f" +{len(device.ports)-5} more"

            dtype = device.ports[0].device_type if device.ports else "unknown"
            mfr   = device.ports[0].manufacturer if device.ports else "unknown"

            inv_data.append([
                device.ip,
                mac_prefix,
                (device.hostname or "—")[:20],
                dtype,
                mfr[:20],
                ports_str,
            ])

        inv_table = Table(inv_data, colWidths=[3*cm, 2.5*cm, 3*cm, 2.5*cm, 3.5*cm, 2*cm])
        inv_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT_BG]),
            ("GRID",         (0,0), (-1,-1), 0.3, BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
        ]))
        elements.append(inv_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements


    def _build_shodan_section(self, result: ScanResult) -> list:
        elements = []

        if not result.exposed_ports:
            return elements

        elements.append(Paragraph("Shodan — WAN Exposure", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        elements.append(Paragraph(
            f"The following services were found indexed by Shodan on your "
            f"public IP address. These ports are visible to anyone on the internet.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 0.3*cm))

        shodan_data = [["Port", "Protocol", "Service", "CVEs", "Last seen"]]
        for ep in result.exposed_ports:
            shodan_data.append([
                str(ep.port),
                ep.protocol,
                ep.service or "—",
                ", ".join(ep.cves[:2]) if ep.cves else "None",
                ep.last_seen.strftime("%Y-%m-%d") if ep.last_seen else "—",
            ])

        shodan_table = Table(shodan_data, colWidths=[2*cm, 2.5*cm, 3*cm, 5*cm, 3*cm])
        shodan_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), DARK),
            ("TEXTCOLOR",    (0,0), (-1,0), colors.white),
            ("FONTNAME",     (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",     (0,0), (-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white, LIGHT_BG]),
            ("GRID",         (0,0), (-1,-1), 0.3, BORDER),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ]))
        elements.append(shodan_table)
        elements.append(Spacer(1, 0.5*cm))
        return elements


    def _build_google_dorks(self, result: ScanResult) -> list:
        elements = []

        # Load dorks from fingerprints
        exposed_types = set()
        for corr in result.correlations:
            if corr.device.ports:
                exposed_types.add(corr.device.ports[0].device_type)

        dorks = self._get_dorks_for_types(exposed_types)
        if not dorks:
            return elements

        elements.append(Paragraph("Google Dorks — How Attackers Could Find You",
                                  self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(
            "Based on the devices found on your network, the following Google "
            "search queries could potentially locate similar exposed devices "
            "worldwide  including yours if your ports remain open. "
            "This section is provided for educational purposes only.",
            self.styles["Body"]
        ))
        elements.append(Spacer(1, 0.3*cm))

        for device_type, type_dorks in dorks.items():
            elements.append(Paragraph(
                f"{device_type.replace('_', ' ').title()}",
                self.styles["AlertTitle"]
            ))
            for dork in type_dorks:
                elements.append(Paragraph(f"  {dork}", self.styles["Code"]))
            elements.append(Spacer(1, 0.2*cm))

        elements.append(Spacer(1, 0.3*cm))
        return elements

    def _build_remediation(self, result: ScanResult) -> list:
        elements = []
        elements.append(PageBreak())
        elements.append(Paragraph("Remediation Guide", self.styles["SectionHeader"]))
        elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
        elements.append(Spacer(1, 0.3*cm))

        if not result.correlations and not result.upnp_leaks:
            elements.append(Paragraph(
                "No critical findings detected. No immediate remediation required.",
                self.styles["Body"]
            ))
            return elements

        # Step 1 — Disable UPnP
        elements.append(Paragraph("Step 1 — Disable UPnP on your router",
                                  self.styles["AlertTitle"]))
        elements.append(Paragraph(
            "UPnP (Universal Plug and Play) allows devices to automatically open "
            "ports on your router without your knowledge. Disabling it is the "
            "single most effective step you can take.",
            self.styles["Body"]
        ))

        router_steps = {
            "ASUS":    "Advanced Settings → WAN → UPnP → Disable",
            "TP-Link": "Advanced → NAT Forwarding → UPnP → Disable",
            "Netgear": "Advanced → Advanced Setup → UPnP → Disable",
            "Linksys": "Security → Apps and Gaming → UPnP → Disable",
            "MikroTik":"IP → UPnP → Disable",
        }
        for brand, path in router_steps.items():
            elements.append(Paragraph(
                f"<b>{brand}:</b> {path}", self.styles["Body"]
            ))

        elements.append(Spacer(1, 0.3*cm))

        # Step 2 — Review port forwarding
        elements.append(Paragraph("Step 2 — Review and remove port forwarding rules",
                                  self.styles["AlertTitle"]))
        elements.append(Paragraph(
            "Check your router's port forwarding table and remove any rules "
            "you did not intentionally create, particularly for the following ports:",
            self.styles["Body"]
        ))

        exposed_ports = [str(ep.port) for ep in result.exposed_ports]
        if exposed_ports:
            elements.append(Paragraph(
                f"Exposed ports to check: {', '.join(exposed_ports)}",
                self.styles["Code"]
            ))

        elements.append(Spacer(1, 0.3*cm))

        # Step 3 — Per device
        if result.correlations:
            elements.append(Paragraph("Step 3 — Per-device actions",
                                      self.styles["AlertTitle"]))
            for corr in result.correlations:
                if corr.device.ports:
                    op = corr.device.ports[0]
                    elements.append(Paragraph(
                        f"<b>{op.manufacturer} {op.device_type}</b> "
                        f"({corr.device.ip}) — port {corr.exposed_port.port}: "
                        f"Update firmware, change default credentials, "
                        f"and restrict access to local network only.",
                        self.styles["Body"]
                    ))

        elements.append(Spacer(1, 0.3*cm))

        # Step 4 — Verify
        elements.append(Paragraph("Step 4 — Verify the fix",
                                  self.styles["AlertTitle"]))
        elements.append(Paragraph(
            "After making changes, run Muhafiz again. If the correlation "
            "no longer appears, the port has been successfully closed. ",
            self.styles["Body"]
        ))

        return elements


    def _header_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#6c757d"))

        # Header
        canvas.drawString(2*cm, A4[1] - 1.2*cm, "MUHAFIZ — Network Security Report")
        canvas.drawRightString(A4[0] - 2*cm, A4[1] - 1.2*cm,
                               datetime.utcnow().strftime("%Y-%m-%d"))

        # Footer
        canvas.drawString(2*cm, 0.8*cm, "Generated by Muhafiz ASM Tool — Confidential")
        canvas.drawRightString(A4[0] - 2*cm, 0.8*cm, f"Page {doc.page}")

        # Header line
        canvas.setStrokeColor(BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, A4[1] - 1.4*cm, A4[0] - 2*cm, A4[1] - 1.4*cm)
        canvas.line(2*cm, 1.1*cm, A4[0] - 2*cm, 1.1*cm)

        canvas.restoreState()


    def _get_dorks_for_types(self, device_types: set) -> dict:
        """
        Returns Google Dorks relevant to the exposed device types.
        These are sourced from real OSINT research.
        """
        DORKS = {
            "ip_camera": [
                'intitle:"Live View / - AXIS"',
                'inurl:"/view/index.shtml"',
                'intitle:"IP Camera" inurl:"/img/video.mjpeg"',
                'inurl:"/cgi-bin/viewer/video.jpg"',
                'intitle:"WebcamXP 5"',
                'inurl:"/mjpg/video.mjpg"',
                'inurl:"ViewerFrame?Mode=Motion"',
                'intitle:"IPCam Client"',
            ],
            "dvr": [
                'inurl:"/dvr/login.htm"',
                'intitle:"DVR Web Viewer"',
                'inurl:"/viewer/live/index.html"',
                'intitle:"Network Video Recorder"',
            ],
            "nas": [
                'intitle:"DiskStation" inurl:":5000"',
                'intitle:"QNAP Turbo NAS"',
                'intitle:"WD My Cloud"',
            ],
            "router": [
                'intitle:"Router" inurl:"admin"',
                'intitle:"ASUS Wireless Router"',
                'intitle:"TP-LINK" inurl:"userRpm"',
            ],
        }

        result = {}
        for dtype in device_types:
            if dtype in DORKS:
                result[dtype] = DORKS[dtype]
        return result