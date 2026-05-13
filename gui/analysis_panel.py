"""
GhostTrace — AI Analysis Panel (fixed scrollable layout)
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QComboBox, QTextEdit, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
COMBO_STYLE = "QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;min-height:28px;}QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;selection-background-color:#111820;}"
TEXT_STYLE  = "QTextEdit{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:10px;}QTextEdit:focus{border-color:#00c8ff;}"


class AnalysisWorker(QThread):
    result   = pyqtSignal(str)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, mode, artifact, context, all_artifacts):
        super().__init__()
        self.mode          = mode
        self.artifact      = artifact
        self.context       = context
        self.all_artifacts = all_artifacts

    def run(self):
        try:
            self.progress.emit("Connecting to AI...")
            from ai.analyzer import ForensicAnalyzer
            analyzer = ForensicAnalyzer()
            self.progress.emit(f"Sending to {analyzer.get_backend_name()}...")

            mode = self.mode
            if mode == "full":
                result = analyzer.full_analysis(self.artifact, self.context)
            elif mode == "iocs":
                result = analyzer.extract_iocs(self.artifact.get("content",""), self.artifact.get("name",""))
            elif mode == "timeline":
                result = analyzer.build_timeline([self.artifact])
            elif mode == "anti_forensics":
                result = analyzer.detect_anti_forensics(self.artifact.get("content",""))
            elif mode == "correlate":
                result = analyzer.correlate(self.all_artifacts)
            elif mode == "profile":
                result = analyzer.profile_attacker(self.artifact.get("content",""))
            elif mode == "query":
                result = analyzer.answer_query(self.context, {
                    "case_id": self.artifact.get("case_id",""),
                    "evidence_summary": self.artifact.get("content","")[:2000],
                    "iocs_summary": "", "timeline_summary": "",
                })
            else:
                result = analyzer.full_analysis(self.artifact, self.context)

            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class AnalysisPanel(QWidget):

    iocs_extracted = pyqtSignal(list)
    timeline_built = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.worker         = None
        self._build_ui()

    def set_evidence(self, items):
        self.evidence_items = items
        self._refresh_combo()

    def _build_ui(self):
        # Outer layout — just title + scroll area
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("AI ANALYSIS ENGINE")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)

        sub = QLabel("// OpenRouter reads your evidence and returns forensic intelligence")
        sub.setStyleSheet("color:#3d5068;font-size:11px;")
        outer.addWidget(sub)

        # Single scroll area containing EVERYTHING below title
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")

        content = QWidget()
        content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0,8,0,8)
        cl.setSpacing(12)

        # ── Controls card ──
        ctrl = QFrame()
        ctrl.setStyleSheet(CARD_STYLE)
        ctrl_l = QVBoxLayout(ctrl)
        ctrl_l.setContentsMargins(16,14,16,14)
        ctrl_l.setSpacing(10)

        ct = QLabel("// SELECT ARTIFACT & ANALYSIS MODE")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ctrl_l.addWidget(ct)

        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.artifact_combo = QComboBox()
        self.artifact_combo.setStyleSheet(COMBO_STYLE)
        self.artifact_combo.addItem("-- Select evidence item --")
        self.mode_combo = QComboBox()
        self.mode_combo.setStyleSheet(COMBO_STYLE)
        self.mode_combo.addItems([
            "Full Forensic Analysis","Extract IOCs","Build Timeline",
            "Detect Anti-Forensics","Correlate All Evidence","Profile Attacker",
        ])
        row1.addWidget(self.artifact_combo, 2)
        row1.addWidget(self.mode_combo, 2)
        ctrl_l.addLayout(row1)

        self.context_input = QTextEdit()
        self.context_input.setPlaceholderText("Additional context (optional) — suspect processes, IP ranges, timeframe...")
        self.context_input.setFixedHeight(60)
        self.context_input.setStyleSheet(TEXT_STYLE)
        ctrl_l.addWidget(self.context_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.run_btn = QPushButton("▶  Run Analysis")
        self.run_btn.setStyleSheet(BTN_PRIMARY)
        self.run_btn.clicked.connect(self._run_analysis)
        self.all_btn = QPushButton("▶▶  Analyze All")
        self.all_btn.setStyleSheet(BTN_NORMAL)
        self.all_btn.clicked.connect(self._run_all)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(BTN_NORMAL)
        self.clear_btn.clicked.connect(self._clear_output)
        btn_row.addWidget(self.run_btn)
        btn_row.addWidget(self.all_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.clear_btn)
        ctrl_l.addLayout(btn_row)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ctrl_l.addWidget(self.progress_label)

        cl.addWidget(ctrl)

        # ── Output card ──
        out_frame = QFrame()
        out_frame.setStyleSheet(CARD_STYLE)
        out_l = QVBoxLayout(out_frame)
        out_l.setContentsMargins(16,14,16,14)
        out_l.setSpacing(8)

        out_header = QHBoxLayout()
        out_title = QLabel("// ANALYSIS OUTPUT")
        out_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        self.backend_label = QLabel("AI: —")
        self.backend_label.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
        out_header.addWidget(out_title)
        out_header.addStretch()
        out_header.addWidget(self.backend_label)
        out_l.addLayout(out_header)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumHeight(300)
        self.output_text.setStyleSheet(TEXT_STYLE)
        self.output_text.setPlaceholderText(
            "Analysis results will appear here...\n\n"
            "Select an evidence item and analysis mode above, then click Run Analysis."
        )
        out_l.addWidget(self.output_text)

        cl.addWidget(out_frame)

        # ── Forensic Query card ──
        query_frame = QFrame()
        query_frame.setStyleSheet(CARD_STYLE)
        ql = QVBoxLayout(query_frame)
        ql.setContentsMargins(16,14,16,14)
        ql.setSpacing(8)

        qt_label = QLabel("// FORENSIC QUERY — ask anything about your evidence")
        qt_label.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ql.addWidget(qt_label)

        self.query_input = QTextEdit()
        self.query_input.setFixedHeight(60)
        self.query_input.setPlaceholderText(
            "e.g. 'What processes were injecting into lsass.exe?'  |  "
            "'Identify lateral movement'  |  'What was exfiltrated?'"
        )
        self.query_input.setStyleSheet(TEXT_STYLE)
        ql.addWidget(self.query_input)

        query_btn = QPushButton("▶  Ask Forensic AI")
        query_btn.setStyleSheet(BTN_PRIMARY)
        query_btn.setFixedWidth(160)
        query_btn.clicked.connect(self._run_query)
        ql.addWidget(query_btn)

        self.query_output = QTextEdit()
        self.query_output.setReadOnly(True)
        self.query_output.setMinimumHeight(120)
        self.query_output.setStyleSheet(
            TEXT_STYLE.replace("color:#cdd6e3", "color:#00ff9d")
        )
        self.query_output.setPlaceholderText("Query response will appear here...")
        ql.addWidget(self.query_output)

        cl.addWidget(query_frame)
        cl.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _refresh_combo(self):
        self.artifact_combo.clear()
        self.artifact_combo.addItem("-- Select evidence item --")
        for item in self.evidence_items:
            self.artifact_combo.addItem(f"{item['id']}: {item['name']}")

    def _get_selected(self):
        idx = self.artifact_combo.currentIndex()
        if idx <= 0 or idx - 1 >= len(self.evidence_items):
            return None
        return self.evidence_items[idx - 1]

    def _mode_key(self):
        return {
            "Full Forensic Analysis":  "full",
            "Extract IOCs":            "iocs",
            "Build Timeline":          "timeline",
            "Detect Anti-Forensics":   "anti_forensics",
            "Correlate All Evidence":  "correlate",
            "Profile Attacker":        "profile",
        }.get(self.mode_combo.currentText(), "full")

    def _run_analysis(self):
        artifact = self._get_selected()
        mode     = self._mode_key()
        if mode != "correlate" and artifact is None:
            self.progress_label.setText("Select an evidence item first.")
            return
        if artifact is None:
            artifact = {"name":"All Evidence","type":"combined","content":"","case_id":""}

        self._set_running(True)
        self.output_text.clear()
        self.output_text.append(
            f"[GhostTrace AI] Analyzing: {artifact.get('name','')} — Mode: {self.mode_combo.currentText()}\n"
            f"{'─'*60}\n"
        )

        self.worker = AnalysisWorker(mode, artifact, self.context_input.toPlainText(), self.evidence_items)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(self._on_progress)
        self.worker.start()

    def _run_all(self):
        if not self.evidence_items:
            self.progress_label.setText("Load evidence first.")
            return
        self._set_running(True)
        self.output_text.clear()
        self.output_text.append(f"[GhostTrace AI] Correlating {len(self.evidence_items)} evidence items...\n{'─'*60}\n")

        combined = {
            "name": "All Evidence", "type": "combined", "case_id": "",
            "content": "\n\n".join(f"[{i['name']}]\n{i.get('content','')[:1500]}" for i in self.evidence_items),
        }
        self.worker = AnalysisWorker("full", combined, self.context_input.toPlainText(), self.evidence_items)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(self._on_progress)
        self.worker.start()

    def _run_query(self):
        question = self.query_input.toPlainText().strip()
        if not question or not self.evidence_items:
            self.query_output.setPlainText("Load evidence and type a question first.")
            return
        self.query_output.setPlainText("Querying AI...")
        self._set_running(True)
        artifact = {
            "name": "Query", "type": "query", "case_id": "",
            "content": "\n".join(f"{i['name']}: {i.get('content','')[:800]}" for i in self.evidence_items),
        }
        self.worker = AnalysisWorker("query", artifact, question, self.evidence_items)
        self.worker.result.connect(self._on_query_result)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(self._on_progress)
        self.worker.start()

    def _on_result(self, text):
        self._set_running(False)
        self.output_text.append(text)
        if self.mode_combo.currentText() == "Extract IOCs":
            self._parse_iocs(text)
        if self.mode_combo.currentText() == "Build Timeline":
            self._parse_timeline(text)
        try:
            from ai.analyzer import ForensicAnalyzer
            self.backend_label.setText(f"AI: {ForensicAnalyzer().get_backend_name()}")
        except Exception:
            pass

    def _on_query_result(self, text):
        self._set_running(False)
        self.query_output.setPlainText(text)

    def _on_error(self, err):
        self._set_running(False)
        self.output_text.append(f"\n[ERROR] {err}\n\nCheck your API key in .env file.")

    def _on_progress(self, msg):
        self.progress_label.setText(msg)

    def _set_running(self, running):
        self.run_btn.setEnabled(not running)
        self.all_btn.setEnabled(not running)
        self.progress_label.setText("Running..." if running else "Done.")

    def _clear_output(self):
        self.output_text.clear()
        self.progress_label.setText("")

    def _parse_iocs(self, text):
        try:
            clean = text.replace("```json","").replace("```","").strip()
            s = clean.find("["); e = clean.rfind("]") + 1
            if s != -1 and e > s:
                iocs = json.loads(clean[s:e])
                if isinstance(iocs, list):
                    self.iocs_extracted.emit(iocs)
        except Exception:
            pass

    def _parse_timeline(self, text):
        try:
            clean = text.replace("```json","").replace("```","").strip()
            s = clean.find("["); e = clean.rfind("]") + 1
            if s != -1 and e > s:
                events = json.loads(clean[s:e])
                if isinstance(events, list):
                    self.timeline_built.emit(events)
        except Exception:
            pass