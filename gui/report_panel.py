"""
GhostTrace - Auto Report Panel
Generates court-ready PDF forensic reports from all case data.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTextEdit, QFileDialog, QMessageBox,
    QLineEdit, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_SUCCESS = "QPushButton{background:rgba(0,255,157,0.1);border:1px solid #00ff9d;border-radius:4px;color:#00ff9d;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,255,157,0.2);}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
INPUT_STYLE = "QLineEdit,QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QLineEdit:focus,QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"


class NarrativeWorker(QThread):
    result = pyqtSignal(str)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, case_data):
        super().__init__()
        self.case_data = case_data

    def run(self):
        try:
            self.status.emit("Generating AI narrative...")
            from ai.analyzer import ForensicAnalyzer
            analyzer = ForensicAnalyzer()
            result = analyzer.generate_narrative(self.case_data)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class ReportPanel(QWidget):

    def __init__(self):
        super().__init__()
        self.case_data   = {}
        self.narrative   = ""
        self.worker      = None
        self._build_ui()

    def update_case_data(self, data: dict):
        """Called from main window with all case data."""
        self.case_data = data
        evidence = data.get("evidence", [])
        self.ev_combo.blockSignals(True)
        self.ev_combo.clear()
        self.ev_combo.addItem("All Evidence")
        for e in evidence:
            self.ev_combo.addItem(f"{e.get('id','?')}: {e.get('name','?')}")
        self.ev_combo.blockSignals(False)
        self._refresh_summary()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("AUTO REPORT")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)
        sub = QLabel("// AI-generated court-ready forensic report - PDF and text export")
        sub.setStyleSheet("color:#3d5068;font-size:11px;")
        outer.addWidget(sub)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")
        content = QWidget(); content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content); cl.setContentsMargins(0,8,0,8); cl.setSpacing(12)

        # ── Case summary ──
        summary_frame = QFrame(); summary_frame.setStyleSheet(CARD_STYLE)
        sum_l = QVBoxLayout(summary_frame); sum_l.setContentsMargins(16,12,16,12); sum_l.setSpacing(8)
        ct = QLabel("// CASE SUMMARY")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        sum_l.addWidget(ct)

        self.summary_grid = QHBoxLayout(); self.summary_grid.setSpacing(8)
        self.sum_chips = {}
        for key, label, color in [
            ("evidence","EVIDENCE","#00ff9d"),
            ("iocs",    "IOCs",    "#ffb020"),
            ("ttps",    "TTPs",    "#00c8ff"),
            ("events",  "EVENTS",  "#a78bfa"),
        ]:
            chip = QFrame(); chip.setStyleSheet("QFrame{background:#111820;border:1px solid #1c2736;border-radius:4px;}")
            cl2 = QVBoxLayout(chip); cl2.setContentsMargins(14,10,14,10)
            vl = QLabel("0"); vl.setStyleSheet(f"color:{color};font-size:24px;font-weight:bold;font-family:Consolas;"); vl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ll = QLabel(label); ll.setStyleSheet("color:#3d5068;font-size:9px;letter-spacing:1px;font-family:Consolas;"); ll.setAlignment(Qt.AlignmentFlag.AlignCenter)
            cl2.addWidget(vl); cl2.addWidget(ll)
            self.sum_chips[key] = vl
            self.summary_grid.addWidget(chip)
        sum_l.addLayout(self.summary_grid)
        cl.addWidget(summary_frame)

        # ── Report options ──
        opts_frame = QFrame(); opts_frame.setStyleSheet(CARD_STYLE)
        opts_l = QVBoxLayout(opts_frame); opts_l.setContentsMargins(16,12,16,12); opts_l.setSpacing(10)
        ot = QLabel("// REPORT OPTIONS")
        ot.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        opts_l.addWidget(ot)

        row1 = QHBoxLayout(); row1.setSpacing(8)
        self.ev_combo = QComboBox(); self.ev_combo.setStyleSheet(INPUT_STYLE)
        self.ev_combo.addItem("All Evidence")
        self.ev_combo.currentIndexChanged.connect(self._refresh_summary)

        self.risk_input = QLineEdit(); self.risk_input.setPlaceholderText("Risk score (0-100)"); self.risk_input.setStyleSheet(INPUT_STYLE)
        self.class_combo = QComboBox(); self.class_combo.setStyleSheet(INPUT_STYLE)
        self.class_combo.addItems(["CONFIDENTIAL","RESTRICTED","INTERNAL","PUBLIC"])
        row1.addWidget(QLabel("Scope:")); row1.addWidget(self.ev_combo)
        row1.addWidget(QLabel("Risk:")); row1.addWidget(self.risk_input)
        row1.addWidget(QLabel("Classification:")); row1.addWidget(self.class_combo)
        for lbl in [row1.itemAt(0).widget(), row1.itemAt(2).widget(), row1.itemAt(4).widget()]:
            if isinstance(lbl, QLabel): lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
        opts_l.addLayout(row1)

        btn_row = QHBoxLayout(); btn_row.setSpacing(8)
        self.narr_btn = QPushButton("🧠  Generate AI Narrative")
        self.narr_btn.setStyleSheet(BTN_PRIMARY)
        self.narr_btn.clicked.connect(self._generate_narrative)

        self.pdf_btn = QPushButton("⬇  Export PDF")
        self.pdf_btn.setStyleSheet(BTN_SUCCESS)
        self.pdf_btn.clicked.connect(self._export_pdf)

        self.txt_btn = QPushButton("⬇  Export TXT")
        self.txt_btn.setStyleSheet(BTN_NORMAL)
        self.txt_btn.clicked.connect(self._export_txt)

        self.json_btn = QPushButton("⬇  Export JSON")
        self.json_btn.setStyleSheet(BTN_NORMAL)
        self.json_btn.clicked.connect(self._export_json)

        btn_row.addWidget(self.narr_btn)
        btn_row.addWidget(self.pdf_btn)
        btn_row.addWidget(self.txt_btn)
        btn_row.addWidget(self.json_btn)
        btn_row.addStretch()
        opts_l.addLayout(btn_row)

        self.status_label = QLabel("Complete your analysis then export the report.")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        opts_l.addWidget(self.status_label)
        cl.addWidget(opts_frame)

        # ── Report preview ──
        prev_frame = QFrame(); prev_frame.setStyleSheet(CARD_STYLE)
        prev_l = QVBoxLayout(prev_frame); prev_l.setContentsMargins(16,12,16,12); prev_l.setSpacing(8)
        pt = QLabel("// REPORT PREVIEW")
        pt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        prev_l.addWidget(pt)
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setMinimumHeight(400)
        self.preview_text.setStyleSheet("QTextEdit{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:11px;padding:12px;line-height:1.7;}")
        self.preview_text.setPlaceholderText(
            "Report preview will appear here.\n\n"
            "1. Load evidence from Evidence → Intake\n"
            "2. Run AI Analysis, extract IOCs, build timeline\n"
            "3. Click Generate AI Narrative\n"
            "4. Export as PDF or TXT"
        )
        prev_l.addWidget(self.preview_text)
        cl.addWidget(prev_frame)

        cl.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll)

    def _refresh_summary(self):
        data = self._build_report_data()
        self.sum_chips["evidence"].setText(str(len(data.get("evidence",[]))))
        self.sum_chips["iocs"].setText(str(len(data.get("iocs",[]))))
        self.sum_chips["ttps"].setText(str(len(data.get("attack_techniques",{}))))
        self.sum_chips["events"].setText(str(len(data.get("timeline",[]))))
        self._update_preview()

    def _update_preview(self):
        from reports.generator import generate_text
        data = self._build_report_data()
        preview = generate_text(data)
        self.preview_text.setPlainText(preview)

    def _build_report_data(self) -> dict:
        data = dict(self.case_data)
        
        target_name = None
        idx = getattr(self, "ev_combo", QComboBox()).currentIndex()
        evidence_list = self.case_data.get("evidence", [])
        if idx > 0 and (idx - 1) < len(evidence_list):
            target_name = evidence_list[idx - 1].get("name")
            
        if target_name:
            data["evidence"] = [e for e in data.get("evidence", []) if e.get("name") == target_name]
            data["iocs"] = [i for i in data.get("iocs", []) if i.get("source") == target_name]
            data["timeline"] = [e for e in data.get("timeline", []) if e.get("source") == target_name]

        data["risk_score"]  = self.risk_input.text() or data.get("risk_score", "\u2014")
        data["narrative"]   = self.narrative
        data["generated_at"]= __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return data

    def _generate_narrative(self):
        if not self.case_data.get("evidence"):
            self.status_label.setText("Load evidence first.")
            return
        self.narr_btn.setEnabled(False)
        self.status_label.setText("Generating AI narrative...")

        data = self._build_report_data()
        narr_data = {
            "case_id":    data.get("case_id","Unknown"),
            "analyst":    data.get("analyst","Unknown"),
            "device":     data.get("device","Unknown"),
            "risk_score": self.risk_input.text() or "\u2014",
            "findings":   "\n".join(
                f"[{i.get('severity','?')}] {i.get('type','?')}: {i.get('value','?')}"
                for i in data.get("iocs",[])[:10]
            ),
            "timeline": "\n".join(
                f"{e.get('time','?')}: {e.get('desc','?')}"
                for e in data.get("timeline",[])[:8]
            ),
        }

        self.worker = NarrativeWorker(narr_data)
        self.worker.result.connect(self._on_narrative)
        self.worker.error.connect(self._on_error)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_narrative(self, text: str):
        self.narr_btn.setEnabled(True)
        self.narrative = text
        self.status_label.setText("Narrative generated. Export when ready.")
        self._update_preview()

    def _on_error(self, err: str):
        self.narr_btn.setEnabled(True)
        self.status_label.setText(f"Error: {err}")

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export PDF Report",
            f"ghosttrace-report-{self.case_data.get('case_id','case')}.pdf",
            "PDF Files (*.pdf)"
        )
        if not path:
            return
        self.status_label.setText("Generating PDF...")
        try:
            from reports.generator import generate_pdf
            data = self._build_report_data()
            success = generate_pdf(data, path)
            if success:
                self.status_label.setText(f"PDF saved: {path}")
                QMessageBox.information(self, "Report Exported", f"PDF report saved to:\n{path}")
            else:
                self.status_label.setText("PDF generation failed.")
                QMessageBox.warning(self, "Error", "PDF generation failed internally.")
        except ModuleNotFoundError as e:
            if 'fpdf' in str(e).lower():
                self.status_label.setText("PDF Generation Failed: Missing fpdf2")
                QMessageBox.critical(self, "Missing Dependency", "PDF generation requires the 'fpdf2' library.\n\nPlease install it by running:\npip install fpdf2")
            else:
                self.status_label.setText(f"PDF Error: {e}")
                QMessageBox.critical(self, "Error", f"Failed to generate PDF:\n{e}")
        except Exception as e:
            self.status_label.setText("PDF generation error.")
            QMessageBox.critical(self, "Error", f"Unexpected error while generating PDF:\n{e}")

    def _export_txt(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Text Report",
            f"ghosttrace-report-{self.case_data.get('case_id','case')}.txt",
            "Text Files (*.txt)"
        )
        if not path:
            return
        from reports.generator import generate_text
        data = self._build_report_data()
        with open(path, "w") as f:
            f.write(generate_text(data))
        self.status_label.setText(f"TXT saved: {path}")
        QMessageBox.information(self, "Report Exported", f"Text report saved to:\n{path}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON Report",
            f"ghosttrace-report-{self.case_data.get('case_id','case')}.json",
            "JSON Files (*.json)"
        )
        if not path:
            return
        from reports.json_export import save_json
        data = self._build_report_data()
        success = save_json(data, path)
        if success:
            self.status_label.setText(f"JSON saved: {path}")
            QMessageBox.information(self, "Report Exported", f"JSON report saved to:\n{path}")
        else:
            self.status_label.setText("JSON export failed.")
            QMessageBox.warning(self, "Error", "JSON export failed.")
            
    def clear_data(self):
        """Wipe AI narrative and rebuild view when evidence scope changes."""
        self.narrative = ""
        self.status_label.setText("Data cleared. Generate AI narrative again.")
        self._refresh_summary()
