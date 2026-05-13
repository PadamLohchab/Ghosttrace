"""
GhostTrace — ATT&CK Map Panel
MITRE ATT&CK heatmap with detected techniques highlighted.
"""

import re
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QGridLayout, QTextEdit, QToolTip, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont, QCursor


CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
INPUT_STYLE = "QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"

# Full ATT&CK Enterprise tactics
TACTICS = [
    "Reconnaissance", "Resource\nDevelopment", "Initial\nAccess",
    "Execution", "Persistence", "Privilege\nEscalation",
    "Defense\nEvasion", "Credential\nAccess", "Discovery",
    "Lateral\nMovement", "Collection", "C2", "Exfiltration", "Impact"
]

# Techniques per tactic (id, short name)
MATRIX = {
    "Reconnaissance":      [("T1595","Active Scan"),("T1592","Host Info"),("T1589","Credentials"),("T1590","Network Info"),("T1591","Org Info"),("T1598","Phishing Info")],
    "Resource\nDevelopment":[("T1583","Acquire Infra"),("T1584","Compromise Infra"),("T1585","Accounts"),("T1586","Compromise Accts"),("T1587","Capabilities"),("T1588","Obtain Capabilities")],
    "Initial\nAccess":     [("T1189","Drive-by"),("T1190","Exploit Public"),("T1133","External Remote"),("T1200","Hardware"),("T1566","Phishing"),("T1078","Valid Accounts")],
    "Execution":           [("T1059","Command Line"),("T1203","Exploit Client"),("T1559","IPC"),("T1106","Native API"),("T1053","Scheduled Task"),("T1204","User Execution")],
    "Persistence":         [("T1547","Boot Autostart"),("T1037","Boot Scripts"),("T1176","Browser Ext"),("T1554","Compromise Client"),("T1136","Create Account"),("T1543","Create Service")],
    "Privilege\nEscalation":[("T1548","Abuse Elevation"),("T1134","Access Token"),("T1055","Process Inject"),("T1053","Scheduled Task"),("T1078","Valid Accounts"),("T1068","Exploit")],
    "Defense\nEvasion":    [("T1140","Deobfuscate"),("T1562","Impair Defenses"),("T1070","Remove Indicators"),("T1036","Masquerading"),("T1027","Obfuscated Files"),("T1218","Signed Binary")],
    "Credential\nAccess":  [("T1110","Brute Force"),("T1555","Credentials Store"),("T1212","Exploit Auth"),("T1187","Forced Auth"),("T1606","Forge Credentials"),("T1003","OS Credentials")],
    "Discovery":           [("T1087","Account Disc"),("T1010","App Window"),("T1217","Browser Info"),("T1083","File Discovery"),("T1046","Network Scan"),("T1057","Process Disc")],
    "Lateral\nMovement":   [("T1210","Exploit Services"),("T1534","Internal Spear"),("T1570","Lateral Transfer"),("T1563","Remote Service"),("T1021","Remote Services"),("T1091","Removable Media")],
    "Collection":          [("T1560","Archive Data"),("T1123","Audio Capture"),("T1119","Auto Collection"),("T1115","Clipboard"),("T1530","Cloud Storage"),("T1213","Data from Repos")],
    "C2":                  [("T1071","App Layer"),("T1092","Comm via Media"),("T1132","Data Encoding"),("T1001","Data Obfusc"),("T1568","Dynamic Res"),("T1573","Encrypted Chan")],
    "Exfiltration":        [("T1020","Auto Exfil"),("T1030","Data Transfer"),("T1048","Exfil Alt Proto"),("T1041","Exfil C2"),("T1011","Exfil Other Net"),("T1052","Exfil Physical")],
    "Impact":              [("T1531","Account Remove"),("T1485","Data Destruction"),("T1486","Data Encrypted"),("T1565","Data Manip"),("T1491","Defacement"),("T1499","Endpoint DoS")],
}

# Known mapping of technique IDs to tactics
TECHNIQUE_TACTIC = {
    "T1595":"Reconnaissance","T1592":"Reconnaissance","T1589":"Reconnaissance",
    "T1583":"Resource\nDevelopment","T1584":"Resource\nDevelopment","T1588":"Resource\nDevelopment",
    "T1189":"Initial\nAccess","T1190":"Initial\nAccess","T1566":"Initial\nAccess","T1078":"Initial\nAccess",
    "T1059":"Execution","T1203":"Execution","T1106":"Execution","T1053":"Execution","T1204":"Execution",
    "T1547":"Persistence","T1136":"Persistence","T1543":"Persistence","T1037":"Persistence",
    "T1548":"Privilege\nEscalation","T1134":"Privilege\nEscalation","T1055":"Privilege\nEscalation","T1068":"Privilege\nEscalation",
    "T1140":"Defense\nEvasion","T1562":"Defense\nEvasion","T1070":"Defense\nEvasion","T1036":"Defense\nEvasion","T1027":"Defense\nEvasion","T1218":"Defense\nEvasion",
    "T1110":"Credential\nAccess","T1555":"Credential\nAccess","T1003":"Credential\nAccess","T1187":"Credential\nAccess",
    "T1087":"Discovery","T1083":"Discovery","T1046":"Discovery","T1057":"Discovery","T1049":"Discovery",
    "T1210":"Lateral\nMovement","T1021":"Lateral\nMovement","T1091":"Lateral\nMovement","T1570":"Lateral\nMovement",
    "T1560":"Collection","T1119":"Collection","T1115":"Collection","T1213":"Collection",
    "T1071":"C2","T1132":"C2","T1001":"C2","T1568":"C2","T1573":"C2","T1095":"C2",
    "T1020":"Exfiltration","T1048":"Exfiltration","T1041":"Exfiltration","T1052":"Exfiltration","T1030":"Exfiltration",
    "T1485":"Impact","T1486":"Impact","T1491":"Impact","T1499":"Impact","T1531":"Impact",
}


class AttackWorker(QThread):
    result = pyqtSignal(dict)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, evidence_items, existing_text=""):
        super().__init__()
        self.evidence_items = evidence_items
        self.existing_text  = existing_text

    def run(self):
        try:
            self.status.emit("Scanning evidence for ATT&CK techniques...")
            from ai.analyzer import ForensicAnalyzer
            analyzer = ForensicAnalyzer()

            combined = "\n\n".join(
                f"[{i.get('name','?')}]\n{i.get('content','')[:1500]}"
                for i in self.evidence_items
            )

            prompt = f"""You are a MITRE ATT&CK expert. Analyze this forensic evidence and identify all ATT&CK techniques.

For each technique found return the exact technique ID (e.g. T1003, T1562.001).
List ONLY technique IDs, one per line, nothing else.

EVIDENCE:
{combined}

{f'ADDITIONAL CONTEXT:{self.existing_text[:1000]}' if self.existing_text else ''}"""

            raw = analyzer._call(prompt)

            # Extract all T-codes
            pattern = r"T\d{4}(?:\.\d{3})?"
            found   = list(set(re.findall(pattern, raw)))

            # Build result dict
            detected = {}
            for tid in found:
                base = tid.split(".")[0]
                tactic = TECHNIQUE_TACTIC.get(base, "Unknown")
                detected[tid] = {
                    "id":         tid,
                    "tactic":     tactic,
                    "confidence": "confirmed",
                    "evidence":   f"Detected in evidence analysis",
                }

            self.result.emit(detected)

        except Exception as e:
            self.error.emit(str(e))


class TechniqueCell(QPushButton):
    """Single ATT&CK technique cell."""

    def __init__(self, tid: str, name: str, state: str = "none"):
        super().__init__()
        self.tid   = tid
        self.tname = name
        self.state = state
        self.setFixedSize(90, 36)
        self.setToolTip(f"{tid}\n{name}")
        self._apply_style()
        self.clicked.connect(self._on_click)

    def set_state(self, state: str):
        self.state = state
        self._apply_style()

    def _apply_style(self):
        status_text = "Live" if self.state != "none" else "Not Detected"
        self.setToolTip(f"{self.tid} — {self.tname}\nStatus: {status_text}")
        
        base_tt = "QToolTip { background: #ffffff; color: #000000; border: 1px solid #1c2736; font-family: Consolas; font-size: 11px; }"
        
        if self.state == "confirmed":
            self.setStyleSheet(f"""
                QPushButton{{background:rgba(255,61,90,0.3);border:1px solid #ff3d5a;
                border-radius:3px;color:#ff3d5a;font-family:Consolas;font-size:9px;
                font-weight:bold;padding:2px;}}
                QPushButton:hover{{background:rgba(255,61,90,0.5);}}
                {base_tt}
            """)
        elif self.state == "suspected":
            self.setStyleSheet(f"""
                QPushButton{{background:rgba(255,176,32,0.2);border:1px solid #ffb020;
                border-radius:3px;color:#ffb020;font-family:Consolas;font-size:9px;
                padding:2px;}}
                QPushButton:hover{{background:rgba(255,176,32,0.4);}}
                {base_tt}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton{{background:#111820;border:1px solid #1c2736;
                border-radius:3px;color:#3d5068;font-family:Consolas;font-size:9px;
                padding:2px;}}
                QPushButton:hover{{background:#161f2a;color:#6b7f96;}}
                {base_tt}
            """)
        # Truncate name for display
        display = self.tid
        self.setText(display)

    def _on_click(self):
        # We can leave this or match it
        status_text = "Live" if self.state != "none" else "Not Detected"
        QToolTip.showText(QCursor.pos(), f"{self.tid} — {self.tname}\nStatus: {status_text}")


class AttackPanel(QWidget):

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.detected       = {}
        self.cells          = {}
        self.worker         = None
        self.has_run        = False
        # Spinner
        self._spinner_timer  = QTimer(self)
        self._spinner_frames = ["◐","◓","◑","◒"]
        self._spinner_idx    = 0
        self._spinner_btn    = None
        self._spinner_label  = ""
        self._spinner_timer.timeout.connect(self._tick_spinner)
        self._build_ui()

    def set_evidence(self, items):
        self.evidence_items = items
        self._refresh_ev_combo()

    def add_techniques(self, technique_ids: list):
        """Add detected techniques from external analysis."""
        for tid in technique_ids:
            base = tid.split(".")[0]
            if tid not in self.detected:
                self.detected[tid] = {
                    "id":         tid,
                    "tactic":     TECHNIQUE_TACTIC.get(base,"Unknown"),
                    "confidence": "confirmed",
                }
        self._highlight_cells()
        self._update_stats()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("MITRE ATT&CK MAP")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)

        sub = QLabel("// Techniques detected in evidence — red = confirmed, amber = suspected")
        sub.setStyleSheet("color:#3d5068;font-size:11px;")
        outer.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")

        content = QWidget()
        content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0,8,0,8)
        cl.setSpacing(12)

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
        ev_hint = QLabel("Scan a single artifact or all evidence for ATT\u0026CK techniques.")
        ev_hint.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ev_row.addWidget(ev_hint, 2)
        ev_l.addLayout(ev_row)
        cl.addWidget(ev_card)

        # ── Stats + controls ──
        ctrl = QFrame()
        ctrl.setStyleSheet(CARD_STYLE)
        ctrl_l = QVBoxLayout(ctrl)
        ctrl_l.setContentsMargins(16,12,16,12)
        ctrl_l.setSpacing(10)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(0)

        self.stat_labels = {}
        for key, label, color in [
            ("total",     "TECHNIQUES",  "#cdd6e3"),
            ("confirmed", "CONFIRMED",   "#ff3d5a"),
            ("suspected", "SUSPECTED",   "#ffb020"),
            ("tactics",   "TACTICS HIT", "#00c8ff"),
        ]:
            chip = QWidget()
            chip_l = QVBoxLayout(chip)
            chip_l.setContentsMargins(20,4,20,4)
            vl = QLabel("0")
            vl.setStyleSheet(f"color:{color};font-size:24px;font-weight:bold;font-family:Consolas;")
            vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ll = QLabel(label)
            ll.setStyleSheet("color:#3d5068;font-size:9px;letter-spacing:1px;font-family:Consolas;")
            ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
            chip_l.addWidget(vl)
            chip_l.addWidget(ll)
            self.stat_labels[key] = vl
            stats_row.addWidget(chip)

        stats_row.addStretch()

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        stats_row.addWidget(self.status_label)

        ctrl_l.addLayout(stats_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        scan_btn = QPushButton("🔍  AI Scan Evidence")
        scan_btn.setStyleSheet(BTN_PRIMARY)
        scan_btn.clicked.connect(self._scan)
        self.scan_btn = scan_btn
        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(BTN_NORMAL)
        clear_btn.clicked.connect(self._clear)
        btn_row.addWidget(scan_btn)
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        ctrl_l.addLayout(btn_row)

        # Legend
        legend_row = QHBoxLayout()
        legend_row.setSpacing(16)
        for color, label in [("#ff3d5a","Confirmed"),("#ffb020","Suspected"),("#3d5068","Not detected")]:
            dot = QLabel("■")
            dot.setStyleSheet(f"color:{color};font-size:12px;")
            lbl = QLabel(label)
            lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
            legend_row.addWidget(dot)
            legend_row.addWidget(lbl)
        legend_row.addStretch()
        ctrl_l.addLayout(legend_row)

        cl.addWidget(ctrl)

        # ── ATT&CK Matrix ──
        matrix_frame = QFrame()
        matrix_frame.setStyleSheet(CARD_STYLE)
        matrix_l = QVBoxLayout(matrix_frame)
        matrix_l.setContentsMargins(16,12,16,12)
        matrix_l.setSpacing(8)

        mt = QLabel("// ATT&CK ENTERPRISE MATRIX")
        mt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;margin-bottom:4px;")
        matrix_l.addWidget(mt)

        # Tactic headers
        header_row = QHBoxLayout()
        header_row.setSpacing(4)
        for tactic in TACTICS:
            lbl = QLabel(tactic)
            lbl.setFixedWidth(90)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setStyleSheet("color:#3d5068;font-size:8px;font-family:Consolas;letter-spacing:0.5px;")
            header_row.addWidget(lbl)
        header_row.addStretch()
        matrix_l.addLayout(header_row)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("border:1px solid #1c2736;")
        matrix_l.addWidget(div)

        # Technique cells — 6 rows
        self.cells = {}
        for row_idx in range(6):
            row_layout = QHBoxLayout()
            row_layout.setSpacing(4)
            for tactic in TACTICS:
                techniques = MATRIX.get(tactic, [])
                if row_idx < len(techniques):
                    tid, name = techniques[row_idx]
                    cell = TechniqueCell(tid, name, "none")
                    self.cells[tid] = cell
                    row_layout.addWidget(cell)
                else:
                    spacer = QWidget()
                    spacer.setFixedSize(90,36)
                    spacer.setStyleSheet("background:transparent;")
                    row_layout.addWidget(spacer)
            row_layout.addStretch()
            matrix_l.addLayout(row_layout)

        cl.addWidget(matrix_frame)

        # ── Detected techniques list ──
        det_frame = QFrame()
        det_frame.setStyleSheet(CARD_STYLE)
        det_l = QVBoxLayout(det_frame)
        det_l.setContentsMargins(16,12,16,12)
        det_l.setSpacing(8)

        det_title = QLabel("// DETECTED TECHNIQUES")
        det_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        det_l.addWidget(det_title)

        self.det_text = QTextEdit()
        self.det_text.setReadOnly(True)
        self.det_text.setFixedHeight(160)
        self.det_text.setStyleSheet("""
            QTextEdit{background:#080b0f;border:1px solid #1c2736;border-radius:4px;
            color:#cdd6e3;font-family:Consolas;font-size:11px;padding:8px;}
        """)
        self.det_text.setPlaceholderText("Detected ATT&CK techniques will appear here after scanning...")
        det_l.addWidget(self.det_text)

        cl.addWidget(det_frame)
        cl.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

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

    def _scan(self):
        targets = self._get_selected_evidence()
        if not targets:
            self.status_label.setText("Load evidence first.")
            return
        label = targets[0].get('name','?') if len(targets)==1 else f"{len(targets)} items"
        self.status_label.setText(f"Scanning {label} for ATT&CK techniques...")
        self._start_spinner(self.scan_btn, "🔍  AI Scan Evidence")
        self.worker = AttackWorker(targets)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_scan_error)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_result(self, detected: dict):
        self.has_run = True
        self._stop_spinner(self.scan_btn, "🔍  AI Scan Evidence")
        self.detected.update(detected)
        self._highlight_cells()
        self._update_stats()
        self._update_list()
        self.status_label.setText(f"✓ Done \u2014 {len(self.detected)} techniques detected.")

    def _on_scan_error(self, msg: str):
        self._stop_spinner(self.scan_btn, "🔍  AI Scan Evidence")
        self.status_label.setText(f"⚠  Error: {msg}")

    # ── Spinner helpers ───────────────────────────────────────────────────

    def _start_spinner(self, btn, original_label: str):
        self._spinner_btn   = btn
        self._spinner_label = original_label
        self._spinner_idx   = 0
        btn.setEnabled(False)
        btn.setStyleSheet(
            "QPushButton{background:rgba(0,200,255,0.04);border:1px solid #253345;"
            "border-radius:4px;color:#3d5068;font-family:Consolas;font-size:12px;padding:8px 18px;}"
        )
        self._spinner_timer.start(130)

    def _stop_spinner(self, btn, original_label: str):
        self._spinner_timer.stop()
        btn.setEnabled(True)
        btn.setText(original_label)
        btn.setStyleSheet(BTN_PRIMARY)

    def _tick_spinner(self):
        frame = self._spinner_frames[self._spinner_idx % len(self._spinner_frames)]
        self._spinner_btn.setText(f"{frame}  Working...")
        self._spinner_idx += 1

    def _highlight_cells(self):
        # Reset all
        for cell in self.cells.values():
            cell.set_state("none")
        # Highlight detected
        for tid, data in self.detected.items():
            base = tid.split(".")[0]
            if base in self.cells:
                self.cells[base].set_state(data.get("confidence","confirmed"))
            if tid in self.cells:
                self.cells[tid].set_state(data.get("confidence","confirmed"))

    def _update_stats(self):
        confirmed = sum(1 for d in self.detected.values() if d.get("confidence")=="confirmed")
        suspected = sum(1 for d in self.detected.values() if d.get("confidence")=="suspected")
        tactics   = len(set(d.get("tactic","") for d in self.detected.values()))
        self.stat_labels["total"].setText(str(len(self.detected)))
        self.stat_labels["confirmed"].setText(str(confirmed))
        self.stat_labels["suspected"].setText(str(suspected))
        self.stat_labels["tactics"].setText(str(tactics))

    def _update_list(self):
        self.det_text.clear()
        for tid, data in sorted(self.detected.items()):
            confidence = data.get("confidence","confirmed").upper()
            tactic     = data.get("tactic","Unknown")
            self.det_text.append(f"[{confidence}] {tid} — {tactic}")

    def _clear(self):
        self.detected = {}
        for cell in self.cells.values():
            cell.set_state("none")
        self._update_stats()
        self.det_text.clear()
        self.status_label.setText("Cleared.")

    def get_detected(self):
        return self.detected
