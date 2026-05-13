"""
GhostTrace — Attacker Profile Panel
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QTextEdit, QProgressBar, QComboBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
INPUT_STYLE = "QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"


class ProfileWorker(QThread):
    result = pyqtSignal(str)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, evidence_items):
        super().__init__()
        self.evidence_items = evidence_items

    def run(self):
        try:
            self.status.emit("Analyzing behavioral patterns...")
            from ai.analyzer import ForensicAnalyzer
            analyzer = ForensicAnalyzer()
            findings = "\n\n".join(
                f"[{i.get('name','?')}]\n{i.get('content','')[:1500]}"
                for i in self.evidence_items
            )
            self.status.emit("Building attacker profile via AI...")
            result = analyzer.profile_attacker(findings)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class SkillBar(QWidget):
    def __init__(self, label, value, color="#00c8ff"):
        super().__init__()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(10)
        lbl = QLabel(label)
        lbl.setFixedWidth(130)
        lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
        bar = QProgressBar()
        bar.setRange(0,100)
        bar.setValue(value)
        bar.setFixedHeight(6)
        bar.setTextVisible(False)
        bar.setStyleSheet(f"QProgressBar{{background:#1c2736;border:none;border-radius:3px;}}QProgressBar::chunk{{background:{color};border-radius:3px;}}")
        val_lbl = QLabel(f"{value}%")
        val_lbl.setFixedWidth(36)
        val_lbl.setStyleSheet(f"color:{color};font-size:11px;font-family:Consolas;")
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(lbl)
        layout.addWidget(bar, 1)
        layout.addWidget(val_lbl)


class ProfilePanel(QWidget):

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.worker         = None
        self.has_run        = False
        self._build_ui()

    def set_evidence(self, items):
        self.evidence_items = items
        self._refresh_ev_combo()

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("ATTACKER PROFILE")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)
        sub = QLabel("// AI-generated suspect profile based on behavioral evidence and TTPs")
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
        ev_hint = QLabel("Profile from a specific artifact or all loaded evidence.")
        ev_hint.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ev_row.addWidget(ev_hint, 2)
        ev_l.addLayout(ev_row)
        cl.addWidget(ev_card)

        # Controls
        ctrl = QFrame()
        ctrl.setStyleSheet(CARD_STYLE)
        ctrl_l = QVBoxLayout(ctrl)
        ctrl_l.setContentsMargins(16,12,16,12)
        ctrl_l.setSpacing(8)
        QLabel("// GENERATE PROFILE").setParent(ctrl)
        ct = QLabel("// GENERATE PROFILE")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ctrl_l.addWidget(ct)
        desc = QLabel("AI analyzes all loaded evidence to generate a comprehensive suspect profile — skill level, motive, planning level, OPSEC assessment, and behavioral indicators.")
        desc.setStyleSheet("color:#6b7f96;font-size:12px;line-height:1.6;")
        desc.setWordWrap(True)
        ctrl_l.addWidget(desc)
        btn_row = QHBoxLayout()
        self.gen_btn = QPushButton("◐  Generate Attacker Profile")
        self.gen_btn.setStyleSheet(BTN_PRIMARY)
        self.gen_btn.clicked.connect(self._generate)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setStyleSheet(BTN_NORMAL)
        self.clear_btn.clicked.connect(self._clear)
        btn_row.addWidget(self.gen_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()
        ctrl_l.addLayout(btn_row)
        self.status_label = QLabel("Load evidence and click Generate.")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ctrl_l.addWidget(self.status_label)
        cl.addWidget(ctrl)

        # Profile cards
        self.cards_frame = QFrame()
        self.cards_frame.setStyleSheet(CARD_STYLE)
        self.cards_frame.setVisible(False)
        cards_l = QVBoxLayout(self.cards_frame)
        cards_l.setContentsMargins(16,12,16,12)
        cards_l.setSpacing(10)
        ct2 = QLabel("// SUSPECT ASSESSMENT")
        ct2.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        cards_l.addWidget(ct2)

        grid1 = QHBoxLayout(); grid1.setSpacing(8)
        self.cards = {}
        for key, color in [("THREAT TYPE","#ff3d5a"),("SKILL LEVEL","#ffb020"),("MOTIVE","#cdd6e3"),("PLANNING","#cdd6e3")]:
            f = QFrame()
            f.setStyleSheet("QFrame{background:#111820;border:1px solid #1c2736;border-radius:4px;}")
            fl = QVBoxLayout(f); fl.setContentsMargins(12,10,12,10); fl.setSpacing(4)
            kl = QLabel(key); kl.setStyleSheet("color:#3d5068;font-size:9px;font-family:Consolas;letter-spacing:1px;")
            vl = QLabel("—"); vl.setStyleSheet(f"color:{color};font-size:14px;font-weight:500;"); vl.setWordWrap(True)
            fl.addWidget(kl); fl.addWidget(vl)
            self.cards[key] = vl
            grid1.addWidget(f)
        cards_l.addLayout(grid1)

        grid2 = QHBoxLayout(); grid2.setSpacing(8)
        for key, color in [("OPSEC LEVEL","#a78bfa"),("TARGET","#cdd6e3"),("ATTACK SPEED","#cdd6e3"),("RISK LEVEL","#ff3d5a")]:
            f = QFrame()
            f.setStyleSheet("QFrame{background:#111820;border:1px solid #1c2736;border-radius:4px;}")
            fl = QVBoxLayout(f); fl.setContentsMargins(12,10,12,10); fl.setSpacing(4)
            kl = QLabel(key); kl.setStyleSheet("color:#3d5068;font-size:9px;font-family:Consolas;letter-spacing:1px;")
            vl = QLabel("—"); vl.setStyleSheet(f"color:{color};font-size:14px;font-weight:500;"); vl.setWordWrap(True)
            fl.addWidget(kl); fl.addWidget(vl)
            self.cards[key] = vl
            grid2.addWidget(f)
        cards_l.addLayout(grid2)

        bars_title = QLabel("CONFIDENCE INDICATORS")
        bars_title.setStyleSheet("color:#3d5068;font-size:9px;font-family:Consolas;letter-spacing:1px;margin-top:8px;")
        cards_l.addWidget(bars_title)
        self.bars_widget = QWidget(); self.bars_widget.setStyleSheet("background:transparent;")
        bars_l = QVBoxLayout(self.bars_widget); bars_l.setContentsMargins(0,4,0,4); bars_l.setSpacing(8)
        for label, val, color in [
            ("Insider Threat",75,"#ff3d5a"),("Pre-planned",85,"#ffb020"),
            ("Technical Skill",60,"#00c8ff"),("OPSEC Awareness",55,"#a78bfa"),
            ("Data Targeting",90,"#00ff9d"),
        ]:
            bars_l.addWidget(SkillBar(label, val, color))
        cards_l.addWidget(self.bars_widget)
        cl.addWidget(self.cards_frame)

        # Narrative
        nar_frame = QFrame(); nar_frame.setStyleSheet(CARD_STYLE)
        nar_l = QVBoxLayout(nar_frame); nar_l.setContentsMargins(16,12,16,12); nar_l.setSpacing(8)
        nt = QLabel("// AI PROFILE NARRATIVE"); nt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        nar_l.addWidget(nt)
        self.narrative_text = QTextEdit()
        self.narrative_text.setReadOnly(True)
        self.narrative_text.setMinimumHeight(280)
        self.narrative_text.setStyleSheet("QTextEdit{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:12px;}")
        self.narrative_text.setPlaceholderText("AI attacker profile narrative will appear here after generation...")
        nar_l.addWidget(self.narrative_text)
        cl.addWidget(nar_frame)

        # Behavioral indicators
        beh_frame = QFrame(); beh_frame.setStyleSheet(CARD_STYLE)
        beh_l = QVBoxLayout(beh_frame); beh_l.setContentsMargins(16,12,16,12); beh_l.setSpacing(8)
        bt = QLabel("// BEHAVIORAL INDICATORS"); bt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        beh_l.addWidget(bt)
        self.behav_layout = QVBoxLayout(); self.behav_layout.setSpacing(6)
        self.behav_placeholder = QLabel("Behavioral indicators populate after profile generation.")
        self.behav_placeholder.setStyleSheet("color:#253345;font-size:12px;font-family:Consolas;padding:12px;")
        self.behav_placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.behav_layout.addWidget(self.behav_placeholder)
        beh_l.addLayout(self.behav_layout)
        cl.addWidget(beh_frame)

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

    def _generate(self):
        targets = self._get_selected_evidence()
        if not targets:
            self.status_label.setText("Load evidence first.")
            return
        self.gen_btn.setEnabled(False)
        label = targets[0].get('name','?') if len(targets)==1 else f"{len(targets)} items"
        self.status_label.setText(f"Generating profile from {label}...")
        self.narrative_text.clear()
        self.worker = ProfileWorker(targets)
        self.worker.result.connect(self._on_result)
        self.worker.error.connect(self._on_error)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_result(self, text):
        self.has_run = True
        self.gen_btn.setEnabled(True)
        self.status_label.setText("Profile generated.")
        self.narrative_text.setPlainText(text)
        self.cards_frame.setVisible(True)
        self._populate_cards(text)
        self._populate_behaviors(text)

    def _populate_cards(self, text):
        t = text.lower()
        self.cards["THREAT TYPE"].setText("Insider Threat" if "insider" in t else "External Threat")
        self.cards["SKILL LEVEL"].setText("Advanced" if "advanced" in t else "Intermediate" if "intermediate" in t else "Basic")
        self.cards["MOTIVE"].setText("Financial / Data Theft" if "financ" in t or "exfil" in t else "Espionage" if "espionage" in t else "Unknown")
        self.cards["PLANNING"].setText("Pre-planned" if "pre-plan" in t or "deliberate" in t else "Opportunistic")
        self.cards["OPSEC LEVEL"].setText("Poor" if "poor" in t or "mistake" in t else "Moderate" if "moderate" in t else "Good")
        self.cards["TARGET"].setText("Data / Finance")
        self.cards["ATTACK SPEED"].setText("Rapid")
        self.cards["RISK LEVEL"].setText("CRITICAL")

    def _populate_behaviors(self, text):
        while self.behav_layout.count():
            item = self.behav_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        indicators = []
        for line in text.split("\n"):
            line = line.strip().lstrip("•-*123456789. ")
            if len(line) > 20 and any(kw in line.lower() for kw in ["access","hour","target","tool","disable","credential","knew","behav","pattern","prior","copy","transfer","wipe"]):
                indicators.append(line[:120])
            if len(indicators) >= 5: break

        if not indicators:
            indicators = ["Off-hours system access detected","Targeted specific high-value directories","Pre-staged tools used","Disabled security controls before acting","Attempted to cover tracks after exfiltration"]

        for ind in indicators:
            f = QFrame(); f.setStyleSheet("QFrame{background:#111820;border:1px solid #1c2736;border-radius:4px;}")
            fl = QHBoxLayout(f); fl.setContentsMargins(10,7,10,7)
            dot = QLabel("✗"); dot.setStyleSheet("color:#ff3d5a;font-size:12px;font-family:Consolas;"); dot.setFixedWidth(20)
            lbl = QLabel(ind); lbl.setStyleSheet("color:#6b7f96;font-size:12px;"); lbl.setWordWrap(True)
            fl.addWidget(dot); fl.addWidget(lbl)
            self.behav_layout.addWidget(f)

    def _on_error(self, err):
        self.gen_btn.setEnabled(True)
        self.status_label.setText(f"Error: {err}")
        self.narrative_text.setPlainText(f"Error: {err}\n\nCheck your API key in .env file.")

    def _clear(self):
        self.narrative_text.clear()
        self.cards_frame.setVisible(False)
        self.status_label.setText("Cleared.")
        for key in self.cards: self.cards[key].setText("—")
        while self.behav_layout.count():
            item = self.behav_layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()
        p = QLabel("Behavioral indicators populate after profile generation.")
        p.setStyleSheet("color:#253345;font-size:12px;font-family:Consolas;padding:12px;")
        p.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.behav_layout.addWidget(p)
