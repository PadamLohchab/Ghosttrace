"""
GhostTrace — Geo Map Panel
Plots suspicious IPs on a world map with threat intel.
"""

import re
import sys
import os
import requests
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTextEdit, QTableWidget, QComboBox,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtSvgWidgets import QSvgWidget
from PyQt6.QtCore import QByteArray


CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
INPUT_STYLE = "QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"

# Approximate world coordinates -> SVG pixel coordinates (800x400 viewbox)
COUNTRY_COORDS = {
    "US":  (160, 175), "United States":  (160, 175),
    "GB":  (310, 130), "United Kingdom": (310, 130),
    "DE":  (340, 130), "Germany":        (340, 130),
    "NL":  (330, 125), "Netherlands":    (330, 125),
    "RU":  (480, 110), "Russia":         (480, 110),
    "CN":  (590, 165), "China":          (590, 165),
    "IN":  (545, 190), "India":          (545, 190),
    "JP":  (650, 165), "Japan":          (650, 165),
    "BR":  (220, 255), "Brazil":         (220, 255),
    "AU":  (625, 295), "Australia":      (625, 295),
    "CA":  (140, 140), "Canada":         (140, 140),
    "FR":  (325, 140), "France":         (325, 140),
    "KR":  (635, 165), "South Korea":    (635, 165),
    "SG":  (600, 215), "Singapore":      (600, 215),
    "UA":  (385, 125), "Ukraine":        (385, 125),
    "NG":  (355, 220), "Nigeria":        (355, 220),
    "ZA":  (385, 285), "South Africa":   (385, 285),
    "TR":  (405, 150), "Turkey":         (405, 150),
    "IR":  (450, 160), "Iran":           (450, 160),
    "Unknown": (400, 200),
}


class GeoWorker(QThread):
    result = pyqtSignal(list)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, iocs: list, evidence_items: list):
        super().__init__()
        self.iocs           = iocs
        self.evidence_items = evidence_items

    def run(self):
        try:
            # Extract IPs from IOCs and evidence
            ips = set()
            for ioc in self.iocs:
                if ioc.get("type") == "IP":
                    ips.add(ioc.get("value",""))

            # Also extract from evidence content
            for item in self.evidence_items:
                content = item.get("content","")
                found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content)
                for ip in found:
                    if not ip.startswith(("127.","192.168.","10.","172.","0.")):
                        ips.add(ip)

            if not ips:
                self.error.emit("No external IPs found in evidence.")
                return

            results = []
            for ip in list(ips)[:15]:  # limit to 15 IPs
                self.status.emit(f"Looking up {ip}...")
                info = self._lookup(ip)
                if info:
                    results.append(info)

            self.result.emit(results)

        except Exception as e:
            self.error.emit(str(e))

    def _lookup(self, ip: str) -> dict:
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,as,query",
                timeout=5
            )
            data = r.json()
            if data.get("status") == "success":
                return {
                    "ip":          ip,
                    "country":     data.get("country","Unknown"),
                    "country_code":data.get("countryCode","UN"),
                    "city":        data.get("city","Unknown"),
                    "isp":         data.get("isp","Unknown"),
                    "org":         data.get("org","Unknown"),
                    "severity":    "HIGH" if self._is_suspicious(ip, data) else "MEDIUM",
                }
        except Exception:
            pass
        return {
            "ip": ip, "country":"Unknown","country_code":"UN",
            "city":"Unknown","isp":"Unknown","org":"Unknown","severity":"MEDIUM"
        }

    def _is_suspicious(self, ip: str, data: dict) -> bool:
        suspicious_orgs = ["tor","vpn","proxy","hosting","datacenter","cloud","digitalocean","hetzner","linode","vultr"]
        org = (data.get("org","") + data.get("isp","")).lower()
        return any(s in org for s in suspicious_orgs)


def build_map_svg(ip_data: list) -> str:
    """Build SVG world map with IP markers."""
    markers = ""
    for i, item in enumerate(ip_data):
        country = item.get("country","Unknown")
        code    = item.get("country_code","UN")
        sev     = item.get("severity","MEDIUM")
        color   = "#ff3d5a" if sev == "HIGH" else "#ffb020"

        coords = COUNTRY_COORDS.get(code) or COUNTRY_COORDS.get(country) or COUNTRY_COORDS["Unknown"]
        # Offset multiple IPs in same country
        x = coords[0] + (i % 3) * 12
        y = coords[1] + (i // 3) * 10

        ip_label = item.get("ip","?")
        city     = item.get("city","")

        markers += f'''
        <g>
          <circle cx="{x}" cy="{y}" r="6" fill="{color}" opacity="0.85">
            <animate attributeName="r" values="5;9;5" dur="2s" repeatCount="indefinite"/>
            <animate attributeName="opacity" values="0.85;0.4;0.85" dur="2s" repeatCount="indefinite"/>
          </circle>
          <circle cx="{x}" cy="{y}" r="4" fill="{color}"/>
          <text x="{x+8}" y="{y-6}" fill="{color}" font-size="9" font-family="Consolas">{ip_label}</text>
          <text x="{x+8}" y="{y+4}" fill="#6b7f96" font-size="8" font-family="Consolas">{city}</text>
        </g>'''

    svg = f'''<svg viewBox="0 0 800 380" xmlns="http://www.w3.org/2000/svg">
  <rect width="800" height="380" fill="#080b0f"/>

  <!-- Grid lines -->
  <line x1="0" y1="190" x2="800" y2="190" stroke="#1c2736" stroke-width="0.5" stroke-dasharray="4,4"/>
  <line x1="400" y1="0" x2="400" y2="380" stroke="#1c2736" stroke-width="0.5" stroke-dasharray="4,4"/>

  <!-- Continents (simplified) -->
  <!-- North America -->
  <path d="M80,100 L200,95 L220,140 L210,190 L180,230 L150,240 L120,210 L90,180 L70,150 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <!-- South America -->
  <path d="M165,240 L230,235 L245,300 L220,350 L185,355 L160,320 L150,275 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <!-- Europe -->
  <path d="M290,100 L390,95 L400,140 L370,160 L320,165 L285,145 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <!-- Africa -->
  <path d="M300,165 L390,160 L405,195 L395,270 L355,300 L315,285 L295,240 L290,200 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <!-- Asia -->
  <path d="M395,90 L680,85 L695,150 L670,200 L600,230 L520,225 L460,200 L415,185 L400,145 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <!-- Australia -->
  <path d="M580,265 L680,260 L695,310 L665,340 L605,335 L575,305 Z"
        fill="#111820" stroke="#1c2736" stroke-width="0.8"/>

  <!-- IP Markers -->
  {markers}

  <!-- Legend -->
  <circle cx="20" cy="355" r="5" fill="#ff3d5a"/>
  <text x="30" y="359" fill="#ff3d5a" font-size="10" font-family="Consolas">High Risk</text>
  <circle cx="100" cy="355" r="5" fill="#ffb020"/>
  <text x="110" y="359" fill="#ffb020" font-size="10" font-family="Consolas">Suspicious</text>
  <circle cx="190" cy="355" r="5" fill="#00c8ff"/>
  <text x="200" y="359" fill="#00c8ff" font-size="10" font-family="Consolas">Victim System</text>
</svg>'''
    return svg


class GeoPanel(QWidget):

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.iocs           = []
        self.ip_data        = []
        self.worker         = None
        self.has_run        = False
        self._build_ui()

    def set_evidence(self, items):
        self.evidence_items = items
        self._refresh_ev_combo()

    def set_iocs(self, iocs):
        self.iocs = iocs

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("GEOLOCATION MAP")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)
        sub = QLabel("// Suspicious IP origins plotted — extracted from PCAP, logs, and IOC registry")
        sub.setStyleSheet("color:#3d5068;font-size:11px;")
        outer.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")
        content = QWidget(); content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content); cl.setContentsMargins(0,8,0,8); cl.setSpacing(12)

        # ── Evidence selector card ──
        ev_card = QFrame()
        ev_card.setStyleSheet(CARD_STYLE)
        ev_l = QVBoxLayout(ev_card)
        ev_l.setContentsMargins(16,12,16,12)
        ev_l.setSpacing(8)
        ev_title = QLabel("// SELECT EVIDENCE")
        ev_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ev_l.addWidget(ev_title)
        ev_row = QHBoxLayout()
        ev_row.setSpacing(8)
        self.ev_combo = QComboBox()
        self.ev_combo.setStyleSheet(INPUT_STYLE)
        self.ev_combo.addItem("All Evidence")
        ev_row.addWidget(self.ev_combo, 3)
        ev_hint = QLabel("Extract IPs from a specific artifact or all loaded evidence.")
        ev_hint.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ev_row.addWidget(ev_hint, 2)
        ev_l.addLayout(ev_row)
        cl.addWidget(ev_card)

        # Controls
        ctrl = QFrame(); ctrl.setStyleSheet(CARD_STYLE)
        ctrl_l = QVBoxLayout(ctrl); ctrl_l.setContentsMargins(16,12,16,12); ctrl_l.setSpacing(8)
        ct = QLabel("// PLOT IP ORIGINS")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ctrl_l.addWidget(ct)
        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        self.plot_btn = QPushButton("◍  Plot All IPs")
        self.plot_btn.setStyleSheet(BTN_PRIMARY)
        self.plot_btn.clicked.connect(self._plot)
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(BTN_NORMAL)
        clear_btn.clicked.connect(self._clear)
        btn_row.addWidget(self.plot_btn); btn_row.addWidget(clear_btn); btn_row.addStretch()
        ctrl_l.addLayout(btn_row)
        self.status_label = QLabel("Load evidence or extract IOCs first, then click Plot All IPs.")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ctrl_l.addWidget(self.status_label)
        cl.addWidget(ctrl)

        # Map display
        map_frame = QFrame(); map_frame.setStyleSheet(CARD_STYLE)
        map_l = QVBoxLayout(map_frame); map_l.setContentsMargins(16,12,16,12); map_l.setSpacing(8)
        mt = QLabel("// WORLD MAP — IP ORIGINS")
        mt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        map_l.addWidget(mt)
        self.svg_widget = QSvgWidget()
        self.svg_widget.setMinimumHeight(300)
        self.svg_widget.setStyleSheet("background:#080b0f;border:1px solid #1c2736;border-radius:4px;")
        self._load_empty_map()
        map_l.addWidget(self.svg_widget)
        cl.addWidget(map_frame)

        # IP details table
        table_frame = QFrame(); table_frame.setStyleSheet(CARD_STYLE)
        tbl_l = QVBoxLayout(table_frame); tbl_l.setContentsMargins(16,12,16,12); tbl_l.setSpacing(8)
        tt = QLabel("// IP DETAILS")
        tt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        tbl_l.addWidget(tt)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["IP","COUNTRY","CITY","ISP / ORG","SEVERITY","STATUS"])
        self.table.setStyleSheet("""
            QTableWidget{background:#080b0f;border:1px solid #1c2736;color:#cdd6e3;font-family:Consolas;font-size:11px;gridline-color:#1c2736;}
            QTableWidget::item{padding:6px 8px;border:none;}
            QTableWidget::item:selected{background:#111820;}
            QHeaderView::section{background:#0d1117;color:#3d5068;font-family:Consolas;font-size:9px;letter-spacing:1px;padding:6px 8px;border:none;border-bottom:1px solid #1c2736;}
        """)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(200)
        tbl_l.addWidget(self.table)
        cl.addWidget(table_frame)

        cl.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _load_empty_map(self):
        empty_svg = '''<svg viewBox="0 0 800 380" xmlns="http://www.w3.org/2000/svg">
  <rect width="800" height="380" fill="#080b0f"/>
  <line x1="0" y1="190" x2="800" y2="190" stroke="#1c2736" stroke-width="0.5" stroke-dasharray="4,4"/>
  <line x1="400" y1="0" x2="400" y2="380" stroke="#1c2736" stroke-width="0.5" stroke-dasharray="4,4"/>
  <path d="M80,100 L200,95 L220,140 L210,190 L180,230 L150,240 L120,210 L90,180 L70,150 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <path d="M165,240 L230,235 L245,300 L220,350 L185,355 L160,320 L150,275 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <path d="M290,100 L390,95 L400,140 L370,160 L320,165 L285,145 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <path d="M300,165 L390,160 L405,195 L395,270 L355,300 L315,285 L295,240 L290,200 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <path d="M395,90 L680,85 L695,150 L670,200 L600,230 L520,225 L460,200 L415,185 L400,145 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <path d="M580,265 L680,260 L695,310 L665,340 L605,335 L575,305 Z" fill="#111820" stroke="#1c2736" stroke-width="0.8"/>
  <text x="380" y="200" fill="#1c2736" font-size="13" font-family="Consolas" text-anchor="middle">Plot IPs to see origin map</text>
</svg>'''
        self.svg_widget.load(QByteArray(empty_svg.encode()))

    def _refresh_ev_combo(self):
        self.ev_combo.clear()
        self.ev_combo.addItem(f"All Evidence ({len(self.evidence_items)} items)")
        for item in self.evidence_items:
            self.ev_combo.addItem(f"{item['id']}: {item['name']}")

    def _get_selected_evidence(self) -> list:
        idx = self.ev_combo.currentIndex()
        if idx <= 0 or not self.evidence_items:
            return self.evidence_items
        real_idx = idx - 1
        if real_idx < len(self.evidence_items):
            return [self.evidence_items[real_idx]]
        return self.evidence_items

    def _plot(self):
        targets = self._get_selected_evidence()
        if not targets and not self.iocs:
            self.status_label.setText("Load evidence or extract IOCs first.")
            return
        self.plot_btn.setEnabled(False)
        label = targets[0].get('name','?') if (targets and len(targets)==1) else f"{len(targets)} items"
        self.status_label.setText(f"Looking up IPs from {label}...")
        self.worker = GeoWorker(self.iocs, targets)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_result(self, ip_data: list):
        self.has_run = True
        self.plot_btn.setEnabled(True)
        self.ip_data = ip_data
        if not ip_data:
            self.status_label.setText("No external IPs found to plot.")
            return
        self.status_label.setText(f"Plotted {len(ip_data)} IPs.")
        # Update map
        svg = build_map_svg(ip_data)
        self.svg_widget.load(QByteArray(svg.encode()))
        # Update table
        self._render_table(ip_data)

    def _render_table(self, ip_data: list):
        self.table.setRowCount(len(ip_data))
        for row, item in enumerate(ip_data):
            sev   = item.get("severity","MEDIUM")
            color = "#ff3d5a" if sev == "HIGH" else "#ffb020"

            cells = [
                (item.get("ip","—"),      "#cdd6e3"),
                (item.get("country","—"), "#cdd6e3"),
                (item.get("city","—"),    "#6b7f96"),
                (item.get("isp","—"),     "#6b7f96"),
                (sev,                     color),
                ("Suspicious" if sev == "HIGH" else "Monitor", color),
            ]
            for col, (val, clr) in enumerate(cells):
                cell = QTableWidgetItem(val)
                cell.setForeground(QColor(clr))
                if col == 4:
                    cell.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
                self.table.setItem(row, col, cell)
                self.table.setRowHeight(row, 30)

    def _on_error(self, err: str):
        self.plot_btn.setEnabled(True)
        self.status_label.setText(f"Error: {err}")

    def _clear(self):
        self.ip_data = []
        self._load_empty_map()
        self.table.setRowCount(0)
        self.status_label.setText("Cleared.")
