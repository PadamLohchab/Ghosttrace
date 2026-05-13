"""
GhostTrace — Incident Reconstruction Panel (fixed scrolling)
"""

import json
from datetime import datetime, timezone

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QLineEdit, QComboBox, QProgressBar
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer


CARD_STYLE  = "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
BTN_PRIMARY = "QPushButton{background:rgba(0,200,255,0.1);border:1px solid #00c8ff;border-radius:4px;color:#00c8ff;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,200,255,0.2);}QPushButton:disabled{border-color:#1c2736;color:#3d5068;}"
BTN_NORMAL  = "QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#6b7f96;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:#111820;color:#cdd6e3;}"
BTN_SUCCESS = "QPushButton{background:rgba(0,255,157,0.1);border:1px solid #00ff9d;border-radius:4px;color:#00ff9d;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(0,255,157,0.2);}"
BTN_WARN    = "QPushButton{background:rgba(255,176,32,0.1);border:1px solid #ffb020;border-radius:4px;color:#ffb020;font-family:Consolas;font-size:12px;padding:8px 18px;}QPushButton:hover{background:rgba(255,176,32,0.2);}"
INPUT_STYLE = "QLineEdit,QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;font-family:Consolas;font-size:12px;padding:6px 10px;}QLineEdit:focus,QComboBox:focus{border-color:#00c8ff;}QComboBox::drop-down{border:none;}QComboBox QAbstractItemView{background:#0d1117;color:#cdd6e3;border:1px solid #1c2736;}"

SEVERITY_COLORS = {"critical":"#ff3d5a","warn":"#ffb020","info":"#00c8ff","alert":"#ff3d5a"}


class TimelineWorker(QThread):
    result = pyqtSignal(list)
    error  = pyqtSignal(str)
    status = pyqtSignal(str)

    def __init__(self, evidence_items):
        super().__init__()
        self.evidence_items = evidence_items

    def run(self):
        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            from ai.analyzer import ForensicAnalyzer
            
            self.status.emit("Running local parsing...")
            local_events = self._local_parse()

            self.status.emit("Refining timeline via AI...")
            analyzer = ForensicAnalyzer()
            raw = analyzer.build_timeline(self.evidence_items)
            ai_events = self._parse_ai(raw)

            final_events = ai_events if ai_events else local_events
            final_events.sort(key=lambda ev: ev.get("time",""))
            self.result.emit(final_events)
        except Exception as e:
            self.error.emit(str(e))

    def _local_parse(self):
        import re
        events = []
        pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})")
        for item in self.evidence_items:
            source_name = item.get("name", "unknown")
            content = item.get("content", "")
            for line in content.splitlines():
                match = pattern.search(line)
                if match:
                    ts = match.group(1)
                    low_line = line.lower()
                    sev = "info"
                    if any(kw in low_line for kw in ["critical", "malware", "ransomware"]):
                        sev = "critical"
                    elif any(kw in low_line for kw in ["alert", "suspicious"]):
                        sev = "alert"
                    events.append({
                        "time": ts,
                        "desc": line.strip(),
                        "source": source_name,
                        "severity": sev
                    })
        return events

    def _parse_ai(self, raw):
        import json
        try:
            clean = raw.replace("```json","").replace("```","").strip()
            s = clean.find("["); e = clean.rfind("]") + 1
            if s != -1 and e > s:
                return json.loads(clean[s:e])
        except Exception:
            pass
        return []


class EventCard(QFrame):
    def __init__(self, event: dict):
        super().__init__()
        sev   = event.get("severity","info").lower()
        color = SEVERITY_COLORS.get(sev, "#00c8ff")
        self.setStyleSheet(f"""
            QFrame{{
                background:#111820;
                border:1px solid #1c2736;
                border-left:3px solid {color};
                border-radius:0px;
                border-top-right-radius:4px;
                border-bottom-right-radius:4px;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12,8,12,8)
        layout.setSpacing(3)

        top = QHBoxLayout()
        time_lbl = QLabel(event.get("time","—"))
        time_lbl.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
        sev_lbl = QLabel(sev.upper())
        sev_lbl.setStyleSheet(f"color:{color};font-size:10px;font-family:Consolas;font-weight:bold;background:transparent;padding:1px 6px;border:1px solid {color};border-radius:3px;")
        top.addWidget(time_lbl)
        top.addStretch()
        top.addWidget(sev_lbl)
        layout.addLayout(top)

        desc = QLabel(event.get("desc","No description"))
        desc.setStyleSheet("color:#cdd6e3;font-size:13px;font-weight:500;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        src = QLabel(f"Source: {event.get('source','Unknown')}")
        src.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
        layout.addWidget(src)


class TimelinePanel(QWidget):

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.events         = []
        self.event_cards    = []
        self.current_step   = -1
        self.playing        = False
        self.worker         = None
        self.has_run        = False
        self.play_timer     = QTimer()
        self.play_timer.timeout.connect(self._next_event)
        # Spinner
        self._spinner_timer  = QTimer(self)
        self._spinner_frames = ["◐","◓","◑","◒"]
        self._spinner_idx    = 0
        self._spinner_timer.timeout.connect(self._tick_spinner)
        self._build_ui()

    def set_evidence(self, items):
        self.evidence_items = items
        self._refresh_ev_combo()

    def add_events(self, events):
        self.events = events
        self._render_all_hidden()
        self.status_label.setText(f"{len(events)} events — click Play to animate.")
        self.event_count_label.setText(f"{len(events)} events")

    def _build_ui(self):
        # Full page scroll — everything scrolls together
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28,24,28,24)
        outer.setSpacing(10)

        title = QLabel("INCIDENT RECONSTRUCTION")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        outer.addWidget(title)

        sub = QLabel("// Attack timeline — animated playback driven by real artifact timestamps")
        sub.setStyleSheet("color:#3d5068;font-size:11px;")
        outer.addWidget(sub)

        # Scroll area wraps everything
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}"
                             "QScrollBar:vertical{background:#0d1117;width:8px;}"
                             "QScrollBar::handle:vertical{background:#1c2736;border-radius:4px;}"
                             "QScrollBar::handle:vertical:hover{background:#253345;}")

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
        ev_hint = QLabel("Build timeline from a single artifact or all loaded evidence.")
        ev_hint.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ev_row.addWidget(ev_hint, 2)
        ev_l.addLayout(ev_row)
        cl.addWidget(ev_card)

        # ── Controls card ──
        ctrl = QFrame()
        ctrl.setStyleSheet(CARD_STYLE)
        ctrl_l = QVBoxLayout(ctrl)
        ctrl_l.setContentsMargins(16,12,16,12)
        ctrl_l.setSpacing(10)

        ct = QLabel("// BUILD & PLAYBACK CONTROLS")
        ct.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        ctrl_l.addWidget(ct)

        time_row = QHBoxLayout()
        time_row.setSpacing(8)
        from_lbl = QLabel("From:")
        from_lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
        self.start_input = QLineEdit()
        self.start_input.setPlaceholderText("Start time (optional)")
        self.start_input.setStyleSheet(INPUT_STYLE)
        to_lbl = QLabel("To:")
        to_lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
        self.end_input = QLineEdit()
        self.end_input.setPlaceholderText("End time (optional)")
        self.end_input.setStyleSheet(INPUT_STYLE)
        time_row.addWidget(from_lbl)
        time_row.addWidget(self.start_input, 2)
        time_row.addWidget(to_lbl)
        time_row.addWidget(self.end_input, 2)
        ctrl_l.addLayout(time_row)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        build_btn = QPushButton("▶  Build Timeline")
        build_btn.setStyleSheet(BTN_PRIMARY)
        build_btn.clicked.connect(self._build_timeline)
        self.build_btn = build_btn
        self.play_btn = QPushButton("▶  Play")
        self.play_btn.setStyleSheet(BTN_SUCCESS)
        self.play_btn.clicked.connect(self._toggle_play)
        reset_btn = QPushButton("↺  Reset")
        reset_btn.setStyleSheet(BTN_NORMAL)
        reset_btn.clicked.connect(self._reset)
        add_btn = QPushButton("+ Add Event")
        add_btn.setStyleSheet(BTN_NORMAL)
        add_btn.clicked.connect(self._add_manual)
        self.speed_combo = QComboBox()
        self.speed_combo.setStyleSheet(INPUT_STYLE)
        self.speed_combo.setFixedWidth(90)
        self.speed_combo.addItems(["1x","2x","3x"])
        speed_lbl = QLabel("Speed:")
        speed_lbl.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")
        btn_row.addWidget(build_btn)
        btn_row.addWidget(self.play_btn)
        btn_row.addWidget(reset_btn)
        btn_row.addWidget(add_btn)
        btn_row.addStretch()
        btn_row.addWidget(speed_lbl)
        btn_row.addWidget(self.speed_combo)
        ctrl_l.addLayout(btn_row)

        prog_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0,100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("QProgressBar{background:#1c2736;border:none;border-radius:2px;}QProgressBar::chunk{background:#ff3d5a;border-radius:2px;}")
        self.risk_label = QLabel("Risk: 0/100")
        self.risk_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;white-space:nowrap;")
        prog_row.addWidget(self.progress_bar, 3)
        prog_row.addWidget(self.risk_label)
        ctrl_l.addLayout(prog_row)

        self.status_label = QLabel("Load evidence and click Build Timeline")
        self.status_label.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        ctrl_l.addWidget(self.status_label)

        cl.addWidget(ctrl)

        # ── Timeline card ──
        tl_frame = QFrame()
        tl_frame.setStyleSheet(CARD_STYLE)
        tl_l = QVBoxLayout(tl_frame)
        tl_l.setContentsMargins(16,12,16,12)
        tl_l.setSpacing(8)

        tl_header = QHBoxLayout()
        tl_title = QLabel("// ATTACK TIMELINE")
        tl_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        self.event_count_label = QLabel("0 events")
        self.event_count_label.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
        tl_header.addWidget(tl_title)
        tl_header.addStretch()
        tl_header.addWidget(self.event_count_label)
        tl_l.addLayout(tl_header)

        # Event cards container — no nested scroll, grows naturally
        self.events_container = QWidget()
        self.events_container.setStyleSheet("background:transparent;")
        self.events_layout = QVBoxLayout(self.events_container)
        self.events_layout.setSpacing(4)
        self.events_layout.setContentsMargins(0,0,0,0)
        self.events_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.empty_label = QLabel("No timeline events yet.\nBuild timeline from evidence or add events manually.")
        self.empty_label.setStyleSheet("color:#253345;font-size:13px;font-family:Consolas;padding:24px;")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.events_layout.addWidget(self.empty_label)

        tl_l.addWidget(self.events_container)
        cl.addWidget(tl_frame)

        # ── AI Summary ──
        self.summary_frame = QFrame()
        self.summary_frame.setStyleSheet("QFrame{background:#0a0f15;border:1px solid rgba(0,200,255,0.2);border-radius:6px;}")
        self.summary_frame.setVisible(False)
        sum_l = QVBoxLayout(self.summary_frame)
        sum_l.setContentsMargins(16,12,16,12)
        sum_title = QLabel("// AI INCIDENT SUMMARY")
        sum_title.setStyleSheet("color:#00c8ff;font-size:10px;font-family:Consolas;letter-spacing:2px;margin-bottom:4px;")
        sum_l.addWidget(sum_title)
        self.summary_text = QLabel("")
        self.summary_text.setStyleSheet("color:#6b7f96;font-size:12px;line-height:1.8;")
        self.summary_text.setWordWrap(True)
        sum_l.addWidget(self.summary_text)
        cl.addWidget(self.summary_frame)

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

    def _build_timeline(self):
        targets = self._get_selected_evidence()
        if not targets:
            self.status_label.setText("Load evidence first from Evidence \u2192 Intake.")
            return
        label = targets[0].get('name','?') if len(targets)==1 else f"{len(targets)} items"
        self.status_label.setText(f"Building timeline from {label} via AI...")
        self._start_spinner(self.build_btn, "▶  Build Timeline")
        self._reset()
        self.worker = TimelineWorker(targets)
        self.worker.result.connect(self._on_built)
        self.worker.error.connect(self._on_build_error)
        self.worker.status.connect(lambda s: self.status_label.setText(s))
        self.worker.start()

    def _on_built(self, events):
        self.has_run = True
        self._stop_spinner(self.build_btn, "▶  Build Timeline")
        if not events:
            self.status_label.setText("No timestamped events found in evidence.")
            return
        self.events = events
        self._render_all_hidden()
        self.status_label.setText(f"✓ {len(events)} events found \u2014 click Play to animate.")
        self.event_count_label.setText(f"{len(events)} events")

    def _on_build_error(self, msg: str):
        self._stop_spinner(self.build_btn, "▶  Build Timeline")
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


    def _render_all_hidden(self):
        # Clear
        while self.events_layout.count():
            item = self.events_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.event_cards = []

        if not self.events:
            lbl = QLabel("No timeline events yet.\nBuild timeline from evidence.")
            lbl.setStyleSheet("color:#253345;font-size:13px;font-family:Consolas;padding:24px;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.events_layout.addWidget(lbl)
            return

        for event in self.events:
            card = EventCard(event)
            card.setVisible(False)
            self.event_cards.append(card)
            self.events_layout.addWidget(card)

        self.event_count_label.setText(f"{len(self.events)} events")

    def _toggle_play(self):
        if self.playing:
            self._pause()
        else:
            self._play()

    def _play(self):
        if not self.events:
            self.status_label.setText("Build timeline first.")
            return
        self.playing = True
        self.play_btn.setStyleSheet(BTN_WARN)
        self.play_btn.setText("⏸  Pause")
        speed_map = {"1x":1100,"2x":600,"3x":300}
        self.play_timer.start(speed_map.get(self.speed_combo.currentText(),1100))
        self._next_event()

    def _pause(self):
        self.playing = False
        self.play_timer.stop()
        self.play_btn.setStyleSheet(BTN_SUCCESS)
        self.play_btn.setText("▶  Play")

    def _next_event(self):
        if self.current_step >= len(self.events) - 1:
            self._pause()
            self._show_summary()
            return
        self.current_step += 1
        if self.current_step < len(self.event_cards):
            self.event_cards[self.current_step].setVisible(True)
        pct = int((self.current_step + 1) / len(self.events) * 100)
        self.progress_bar.setValue(pct)
        risk = min(100, int(pct * 0.87))
        self.risk_label.setText(f"Risk: {risk}/100")
        desc = self.events[self.current_step].get("desc","")[:70]
        self.status_label.setText(f"Event {self.current_step+1}/{len(self.events)}: {desc}...")

    def _show_summary(self):
        if not self.events:
            return
        critical = sum(1 for e in self.events if e.get("severity","") in ["critical","alert"])
        warn     = sum(1 for e in self.events if e.get("severity","") == "warn")
        sources  = len(set(e.get("source","") for e in self.events))
        self.summary_text.setText(
            f"Reconstruction complete. {len(self.events)} events analyzed across {sources} artifact(s). "
            f"{critical} critical and {warn} warning events detected. "
            f"Timeline spans {self.events[0].get('time','?')} to {self.events[-1].get('time','?')}."
        )
        self.summary_frame.setVisible(True)
        self.status_label.setText("Reconstruction complete.")

    def _reset(self):
        self._pause()
        self.current_step = -1
        self.progress_bar.setValue(0)
        self.risk_label.setText("Risk: 0/100")
        self.summary_frame.setVisible(False)
        for card in self.event_cards:
            card.setVisible(False)
        self.status_label.setText("Reset. Click Play to replay.")

    def _add_manual(self):
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Manual Event")
        dialog.setStyleSheet("QDialog{background:#0d1117;color:#cdd6e3;font-family:Consolas;}")
        dialog.setMinimumWidth(420)
        form = QFormLayout(dialog)
        form.setContentsMargins(16,16,16,16)
        form.setSpacing(10)
        time_i = QLineEdit(); time_i.setPlaceholderText("2025-01-15T08:32:00"); time_i.setStyleSheet(INPUT_STYLE)
        desc_i = QLineEdit(); desc_i.setPlaceholderText("Event description"); desc_i.setStyleSheet(INPUT_STYLE)
        src_i  = QLineEdit(); src_i.setPlaceholderText("Source artifact"); src_i.setStyleSheet(INPUT_STYLE)
        sev_c  = QComboBox(); sev_c.addItems(["info","warn","critical"]); sev_c.setStyleSheet(INPUT_STYLE)
        form.addRow("Time:", time_i)
        form.addRow("Description:", desc_i)
        form.addRow("Source:", src_i)
        form.addRow("Severity:", sev_c)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.setStyleSheet("QPushButton{background:transparent;border:1px solid #1c2736;border-radius:4px;color:#cdd6e3;padding:6px 14px;font-family:Consolas;}")
        btns.accepted.connect(dialog.accept)
        btns.rejected.connect(dialog.reject)
        form.addRow(btns)
        if dialog.exec() == QDialog.DialogCode.Accepted and desc_i.text().strip():
            self.events.append({
                "time":     time_i.text().strip() or datetime.now(timezone.utc).isoformat(),
                "desc":     desc_i.text().strip(),
                "source":   src_i.text().strip() or "Manual",
                "severity": sev_c.currentText(),
            })
            self.events.sort(key=lambda ev: ev.get("time",""))
            self._render_all_hidden()
            self.event_count_label.setText(f"{len(self.events)} events")

    def clear_data(self):
        """Wipe events when evidence scope changes."""
        self.events = []
        self.has_run = False
        self._reset()
        self._render_all_hidden()
        self.status_label.setText("Data cleared. Click Build Timeline.")