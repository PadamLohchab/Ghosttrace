"""
GhostTrace — IOC Registry Panel (FIXED & ENHANCED)
Displays, searches, and manages indicators of compromise with dynamic severity.
"""

import re
import json
import csv
from datetime import datetime, timezone

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QScrollArea, QFileDialog, QMessageBox, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QFont

CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
INPUT_STYLE = "QLineEdit,QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QLineEdit:focus,QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"

# FIXED: Added CRITICAL and ensured high-contrast colors
SEVERITY_COLORS = {
    "CRITICAL": "#ff0033", # Bright Red
    "HIGH":     "#ff3d5a", # Soft Red
    "MEDIUM":   "#ffb020", # Orange/Yellow
    "LOW":      "#00ff9d", # Green
    "INFO":     "#00c8ff", # Blue
}

TYPE_COLORS = {
    "IP":       "#00c8ff", "DOMAIN":   "#a78bfa", "HASH":     "#ff3d5a",
    "URL":      "#ffb020", "EMAIL":    "#00ff9d", "REGISTRY": "#f97316",
    "PROCESS":  "#ec4899", "FILENAME": "#84cc16", "USERNAME": "#06b6d4",
    "OTHER":    "#6b7f96",
}

class IOCExtractWorker(QThread):
    result = pyqtSignal(list)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, evidence_items: list):
        super().__init__()
        self.evidence_items = evidence_items

    def run(self):
        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from ai.analyzer import ForensicAnalyzer

            self.status.emit("Initialising AI engine...")
            analyzer = ForensicAnalyzer()
            all_iocs = []

            for item in self.evidence_items:
                self.status.emit(f"Extracting IOCs from {item.get('name', '?')}...")
                raw = analyzer.extract_iocs(
                    item.get("content", ""),
                    item.get("name", "unknown"),
                )
                try:
                    clean = raw.replace("```json", "").replace("```", "").strip()
                    start = clean.find("["); end = clean.rfind("]") + 1
                    if start != -1 and end > start:
                        iocs = json.loads(clean[start:end])
                        for ioc in iocs:
                            # Apply dynamic severity to AI results too
                            ioc["severity"] = self._calculate_severity(ioc.get("type"), ioc.get("value"))
                            ioc["source"]   = item.get("name", "unknown")
                            ioc["added_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                        all_iocs.extend(iocs)
                except Exception:
                    all_iocs.extend(self._regex_extract(item.get("content", ""), item.get("name", "?")))

            self.result.emit(all_iocs)
        except Exception as e:
            self.error.emit(str(e))

    def _calculate_severity(self, ioc_type, value):
        """Intelligent severity assignment logic."""
        if not value: return "MEDIUM"
        val_lower = str(value).lower()
        
        # 1. Critical: Any file hash is a smoking gun
        if ioc_type == "HASH":
            return "CRITICAL"
        
        # 2. High: Suspicious keywords in domains/URLs
        high_risk = ["evil", "cnc", "attack", "payload", "verify", "security-patch", "login-verify", "beacon"]
        if ioc_type in ["DOMAIN", "URL"]:
            if any(k in val_lower for k in high_risk):
                return "HIGH"
        
        # 3. Low: Trusted infrastructure
        trusted_ips = ["8.8.8.8", "1.1.1.1"]
        trusted_domains = ["microsoft.com", "google.com", "apple.com"]
        if (ioc_type == "IP" and value in trusted_ips) or \
           (ioc_type == "DOMAIN" and value in trusted_domains):
            return "LOW"
            
        return "MEDIUM"

    def _regex_extract(self, content: str, source: str) -> list:
        found = []
        patterns = {
            "IP":     r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "DOMAIN": r"\b(?:[a-z0-9\-]+\.)+(?:com|net|org|io|xyz|ru|cn|onion)\b",
            "HASH":   r"\b[a-fA-F0-9]{32,64}\b",
            "URL":    r"https?://[^\s\"'<>]+",
        }
        for ioc_type, pattern in patterns.items():
            for m in set(re.findall(pattern, content, re.IGNORECASE)):
                found.append({
                    "type":     ioc_type, 
                    "value":    m,
                    "severity": self._calculate_severity(ioc_type, m), # FIXED: Dynamic severity
                    "context":  "Regex extracted",
                    "source":   source,
                    "added_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                })
        return found


class IOCPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.iocs           = []
        self.filtered_iocs  = []
        self.evidence_items = []
        self.worker         = None
        self.has_run        = False
        self._spinner_timer  = QTimer(self)
        self._spinner_frames = ["◐","◓","◑","◒"]
        self._spinner_idx    = 0
        self._spinner_btn    = None
        self._spinner_label  = ""
        self._spinner_timer.timeout.connect(self._tick_spinner)
        self._build_ui()

    def set_evidence(self, items: list):
        self.evidence_items = items
        self._refresh_ev_combo()

    def add_iocs(self, iocs: list):
        for ioc in iocs:
            if not any(i.get("value") == ioc.get("value") for i in self.iocs):
                # ensure AI added items also have a severity
                ioc["severity"] = ioc.get("severity", "MEDIUM").upper()
                ioc.setdefault("source",   "AI Analysis")
                ioc.setdefault("added_at", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
                self.iocs.append(ioc)
        self._apply_filter()  # To refresh the table with current filters
        self._update_stats()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(10)

        title = QLabel("IOC REGISTRY")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)

        sub = QLabel("// Indicators of compromise extracted from evidence artifacts")
        sub.setStyleSheet("color:#3d5068;font-size:11px;margin-bottom:4px;")
        outer.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")

        content = QWidget()
        content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 4, 0, 8)
        cl.setSpacing(12)

        # Evidence selector
        ev_card = QFrame()
        ev_card.setStyleSheet(CARD_STYLE)
        ev_l = QVBoxLayout(ev_card)
        ev_l.setContentsMargins(16, 12, 16, 12)
        ev_title = QLabel("// SELECT EVIDENCE")
        ev_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ev_l.addWidget(ev_title)
        ev_row = QHBoxLayout()
        self.ev_combo = QComboBox()
        self.ev_combo.setStyleSheet(INPUT_STYLE)
        self.ev_combo.addItem("All Evidence")
        ev_row.addWidget(self.ev_combo, 3)
        ev_info = QLabel("Select a specific artifact or extract IOCs from all loaded evidence.")
        ev_info.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ev_row.addWidget(ev_info, 2)
        ev_l.addLayout(ev_row)
        cl.addWidget(ev_card)

        # Stats Row (FIXED: Added Critical)
        stats_frame = QFrame()
        stats_frame.setStyleSheet(CARD_STYLE)
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(16, 12, 16, 12)

        self.stat_labels = {}
        for key, label, color in [
            ("total",    "TOTAL IOCs", "#cdd6e3"),
            ("critical", "CRITICAL",   "#ff0033"),
            ("high",     "HIGH",       "#ff3d5a"),
            ("medium",   "MEDIUM",     "#ffb020"),
            ("low",      "LOW",        "#00ff9d"),
        ]:
            chip = QWidget()
            cl2  = QVBoxLayout(chip)
            cl2.setContentsMargins(15, 4, 15, 4)
            vl = QLabel("0")
            vl.setStyleSheet(f"color:{color};font-size:24px;font-weight:bold;font-family:Consolas;")
            vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ll = QLabel(label)
            ll.setStyleSheet("color:#3d5068;font-size:9px;letter-spacing:1px;font-family:Consolas;")
            ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cl2.addWidget(vl)
            cl2.addWidget(ll)
            self.stat_labels[key] = vl
            stats_layout.addWidget(chip)

        stats_layout.addStretch()
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        stats_layout.addWidget(self.status_label)
        cl.addWidget(stats_frame)

        # Controls
        ctrl_frame = QFrame()
        ctrl_frame.setStyleSheet(CARD_STYLE)
        ctrl_layout = QVBoxLayout(ctrl_frame)
        ctrl_layout.setContentsMargins(16, 12, 16, 12)
        ct = QLabel("// SEARCH & FILTER")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ctrl_layout.addWidget(ct)
        row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search IOCs...")
        self.search_input.setStyleSheet(INPUT_STYLE)
        self.search_input.textChanged.connect(self._apply_filter)
        self.type_filter = QComboBox()
        self.type_filter.setStyleSheet(INPUT_STYLE)
        self.type_filter.setFixedWidth(130)
        self.type_filter.addItems(["All Types", "IP", "DOMAIN", "HASH", "URL"])
        self.type_filter.currentTextChanged.connect(self._apply_filter)
        self.sev_filter = QComboBox()
        self.sev_filter.setStyleSheet(INPUT_STYLE)
        self.sev_filter.setFixedWidth(130)
        self.sev_filter.addItems(["All Severity", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.sev_filter.currentTextChanged.connect(self._apply_filter)
        row.addWidget(self.search_input, 3)
        row.addWidget(self.type_filter)
        row.addWidget(self.sev_filter)
        ctrl_layout.addLayout(row)
        
        btn_row = QHBoxLayout()
        extract_btn = QPushButton("🎯  AI Extract IOCs")
        extract_btn.setStyleSheet(BTN_PRIMARY)
        extract_btn.clicked.connect(self._extract_all)
        self.extract_btn = extract_btn
        btn_row.addWidget(extract_btn)
        btn_row.addStretch()
        ctrl_layout.addLayout(btn_row)
        cl.addWidget(ctrl_frame)

        # Table
        table_frame = QFrame()
        table_frame.setStyleSheet(CARD_STYLE)
        table_layout = QVBoxLayout(table_frame)
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["TYPE", "INDICATOR", "SEVERITY", "SOURCE", "CONTEXT", "ADDED"])
        self.table.setStyleSheet("""
            QTableWidget {
                background: #080b0f;
                border: 1px solid #1c2736;
                color: #cdd6e3;
                font-family: Consolas;
                font-size: 11px;
                outline: none;
            }
            QTableWidget::item:hover {
                background: #1c2736;
            }
            QTableWidget::item:selected {
                background: rgba(0,200,255,0.1);
                color: #00c8ff;
            }
        """)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMouseTracking(True)
        self.table.verticalHeader().setVisible(False)
        table_layout.addWidget(self.table)
        cl.addWidget(table_frame)

        scroll.setWidget(content)
        outer.addWidget(scroll)
        self._render_table()

    def _refresh_ev_combo(self):
        self.ev_combo.clear()
        self.ev_combo.addItem(f"All Evidence ({len(self.evidence_items)} items)")
        for item in self.evidence_items:
            self.ev_combo.addItem(f"{item['id']}: {item['name']}")

    def _get_selected_evidence(self) -> list:
        idx = self.ev_combo.currentIndex()
        if idx <= 0 or not self.evidence_items: return self.evidence_items
        return [self.evidence_items[idx-1]]

    def _apply_filter(self):
        search = self.search_input.text().lower()
        type_f = self.type_filter.currentText()
        sev_f  = self.sev_filter.currentText()
        self.filtered_iocs = []
        for ioc in self.iocs:
            if search and search not in ioc.get("value", "").lower(): continue
            if type_f != "All Types" and ioc.get("type", "") != type_f: continue
            if sev_f != "All Severity" and ioc.get("severity", "").upper() != sev_f: continue
            self.filtered_iocs.append(ioc)
        self._render_table()

    def _render_table(self):
        self.table.setRowCount(0)
        if not self.filtered_iocs: return
        self.table.setRowCount(len(self.filtered_iocs))
        for row, ioc in enumerate(self.filtered_iocs):
            severity = ioc.get("severity", "MEDIUM").upper()
            sev_color = SEVERITY_COLORS.get(severity, "#6b7f96")
            
            tooltip = f"Type: {ioc.get('type', 'OTHER')}\nValue: {ioc.get('value', '—')}\nSeverity: {severity}\nSource: {ioc.get('source', '—')}\nContext: {ioc.get('context', '—')}\nStatus: Live"
            
            t_item = QTableWidgetItem(ioc.get("type", "OTHER"))
            t_item.setToolTip(tooltip)
            v_item = QTableWidgetItem(ioc.get("value", "—"))
            v_item.setToolTip(tooltip)
            
            s_item = QTableWidgetItem(severity)
            s_item.setForeground(QColor(sev_color))
            s_item.setFont(QFont("Consolas", 10, QFont.Weight.Bold))
            s_item.setToolTip(tooltip)
            
            src_item = QTableWidgetItem(ioc.get("source", "—"))
            src_item.setToolTip(tooltip)
            cx_item = QTableWidgetItem(ioc.get("context", "—"))
            cx_item.setToolTip(tooltip)
            time_item = QTableWidgetItem(ioc.get("added_at", "—"))
            time_item.setToolTip(tooltip)

            self.table.setItem(row, 0, t_item)
            self.table.setItem(row, 1, v_item)
            self.table.setItem(row, 2, s_item)
            self.table.setItem(row, 3, src_item)
            self.table.setItem(row, 4, cx_item)
            self.table.setItem(row, 5, time_item)

    def _update_stats(self):
        self.stat_labels["total"].setText(str(len(self.iocs)))
        self.stat_labels["critical"].setText(str(sum(1 for i in self.iocs if i.get("severity", "").upper() == "CRITICAL")))
        self.stat_labels["high"].setText(str(sum(1 for i in self.iocs if i.get("severity", "").upper() == "HIGH")))
        self.stat_labels["medium"].setText(str(sum(1 for i in self.iocs if i.get("severity", "").upper() == "MEDIUM")))
        self.stat_labels["low"].setText(str(sum(1 for i in self.iocs if i.get("severity", "").upper() == "LOW")))

    def _extract_all(self):
        targets = self._get_selected_evidence()
        self._start_spinner(self.extract_btn, "🎯  AI Extract IOCs")
        self.worker = IOCExtractWorker(targets)
        self.worker.result.connect(self._on_extracted)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_extracted(self, iocs: list):
        self._stop_spinner(self.extract_btn, "🎯  AI Extract IOCs")
        self.add_iocs(iocs)
        self.status_label.setText(f"✓ Done — {len(iocs)} IOCs extracted.")

    def _start_spinner(self, btn, label):
        self._spinner_btn = btn
        btn.setEnabled(False)
        self._spinner_timer.start(130)

    def _stop_spinner(self, btn, label):
        self._spinner_timer.stop()
        btn.setEnabled(True)
        btn.setText(label)

    def _tick_spinner(self):
        self._spinner_idx += 1
        self._spinner_btn.setText(f"{self._spinner_frames[self._spinner_idx % 4]} Working...")

    def clear_data(self):
        """Wipe AI-generated data when evidence scope changes."""
        self.iocs = []
        self.filtered_iocs = []
        self.has_run = False
        self._apply_filter()
        self._update_stats()
        self.status_label.setText("Data cleared. Run AI extract.")

    def get_iocs(self) -> list:
        return self.iocs
