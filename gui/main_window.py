"""
GhostTrace — Main Window
Live dashboard with real-time stats that update as analysis progresses.
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QFrame, QScrollArea, QTextEdit,
    QComboBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from datetime import datetime, timezone
from gui.evidence_panel import EvidencePanel
from gui.analysis_panel import AnalysisPanel
from gui.ioc_panel      import IOCPanel
from gui.timeline_panel import TimelinePanel
from gui.attack_panel   import AttackPanel
from gui.profile_panel  import ProfilePanel
from gui.geo_panel      import GeoPanel
from gui.report_panel   import ReportPanel


class GlobalStateManager(QObject):
    """Centralised state management for GhostTrace."""
    evidence_changed = pyqtSignal(str) # Emits the active evidence name or ID (or "All Evidence")

    def __init__(self):
        super().__init__()
        self.active_evidence_name = "All Evidence"

    def set_active_evidence(self, name: str):
        if self.active_evidence_name != name:
            self.active_evidence_name = name
            self.evidence_changed.emit(name)


class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("GhostTrace — Dead System Forensics Analyzer")
        self.setMinimumSize(1200, 750)
        self.global_state = GlobalStateManager()
        self._build_ui()
        self._start_clock()

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.setStyleSheet(
            "QMainWindow{background:#080b0f;}"
            "QWidget{background:#080b0f;color:#cdd6e3;font-family:Consolas;}"
            "QLabel{background:transparent;}"
        )
        root = QWidget()
        self.setCentralWidget(root)
        rl = QVBoxLayout(root)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        rl.addWidget(self._build_topbar())
        body = QWidget()
        bl = QHBoxLayout(body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(0)
        bl.addWidget(self._build_sidebar())
        bl.addWidget(self._build_main_area())
        rl.addWidget(body)

    def _build_topbar(self):
        bar = QFrame()
        bar.setFixedHeight(52)
        bar.setStyleSheet("QFrame{background:#0d1117;border-bottom:1px solid #253345;}")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)
        logo = QLabel("GhostTrace  //  DEAD SYSTEM FORENSICS ANALYZER")
        logo.setStyleSheet("color:#00c8ff;font-size:16px;font-weight:bold;letter-spacing:3px;")
        layout.addWidget(logo)
        layout.addStretch()
        self.clock_label = QLabel()
        self.clock_label.setStyleSheet("color:#3d5068;font-size:11px;")
        layout.addWidget(self.clock_label)
        sep = QLabel("  |  ")
        sep.setStyleSheet("color:#1c2736;")
        layout.addWidget(sep)
        self.status_dot = QLabel("● READY")
        self.status_dot.setStyleSheet("color:#00ff9d;font-size:11px;")
        layout.addWidget(self.status_dot)
        return bar

    def _build_sidebar(self):
        sidebar = QFrame()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet("QFrame{background:#0d1117;border-right:1px solid #1c2736;}")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 16, 0, 16)
        layout.setSpacing(0)
        nav_items = [
            ("OVERVIEW",         None, None),
            ("Dashboard",        "▣",  0),
            ("EVIDENCE",         None, None),
            ("Intake",           "⬇",  1),
            ("ANALYSIS",         None, None),
            ("AI Analysis",      "🧠", 2),
            ("IOC Registry",     "◎",  3),
            ("Reconstruction",   "▷",  4),
            ("ATT&CK Map",       "◉",  5),
            ("INTELLIGENCE",     None, None),
            ("Attacker Profile", "◐",  6),
            ("Geo Map",          "◍",  7),
            ("OUTPUT",           None, None),
            ("Auto Report",      "▤",  8),
        ]
        self.nav_buttons = []
        for label, icon, page in nav_items:
            if icon is None:
                lbl = QLabel(label)
                lbl.setStyleSheet(
                    "color:#3d5068;font-size:9px;letter-spacing:2px;"
                    "padding:12px 16px 4px 16px;"
                )
                layout.addWidget(lbl)
            else:
                btn = QPushButton(f"  {icon}   {label}")
                btn.setFixedHeight(36)
                btn.setCheckable(True)
                btn.setStyleSheet(
                    "QPushButton{text-align:left;background:transparent;border:none;"
                    "border-left:2px solid transparent;color:#6b7f96;font-size:13px;"
                    "padding-left:14px;}"
                    "QPushButton:hover{background:#111820;color:#cdd6e3;}"
                    "QPushButton:checked{border-left:2px solid #00c8ff;"
                    "background:#111820;color:#00c8ff;}"
                )
                btn.clicked.connect(lambda _, p=page, b=btn: self._switch_page(p, b))
                layout.addWidget(btn)
                self.nav_buttons.append((btn, page))

        layout.addStretch()

        # Case info box at sidebar bottom
        info_frame = QFrame()
        info_frame.setStyleSheet(
            "QFrame{background:#0a0f15;border:1px solid #1c2736;"
            "border-radius:4px;margin:8px;}"
        )
        il = QVBoxLayout(info_frame)
        il.setContentsMargins(10, 10, 10, 10)
        self.case_info_label = QLabel("CASE: —\nANALYST: —\nEVIDENCE: 0\nIOCs: 0\nRISK: —")
        self.case_info_label.setStyleSheet("color:#3d5068;font-size:10px;line-height:1.8;")
        il.addWidget(self.case_info_label)
        layout.addWidget(info_frame)

        if self.nav_buttons:
            self.nav_buttons[0][0].setChecked(True)
        return sidebar

    def _build_main_area(self):
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background:#080b0f;")

        # Instantiate all panels
        self.evidence_panel = EvidencePanel()
        self.analysis_panel = AnalysisPanel()
        self.ioc_panel      = IOCPanel()
        self.timeline_panel = TimelinePanel()
        self.attack_panel   = AttackPanel()
        self.profile_panel  = ProfilePanel()
        self.geo_panel      = GeoPanel()
        self.report_panel   = ReportPanel()

        # ── Wire signals ──────────────────────────────────────────────────────
        self.evidence_panel.evidence_updated.connect(self._on_evidence_updated)

        # When AI extracts IOCs → push to IOC panel + refresh dashboard
        self.analysis_panel.iocs_extracted.connect(self.ioc_panel.add_iocs)
        self.analysis_panel.iocs_extracted.connect(lambda _: self._update_dashboard())

        # When timeline is built → push to timeline panel + refresh dashboard
        self.analysis_panel.timeline_built.connect(self.timeline_panel.add_events)
        self.analysis_panel.timeline_built.connect(lambda _: self._update_dashboard())

        # Wire up Global State
        self.global_state.evidence_changed.connect(self._on_global_evidence_changed)
        
        # Ensure child combats trigger the global state change
        for panel in (self.ioc_panel, self.timeline_panel, self.attack_panel, self.report_panel):
            if hasattr(panel, "ev_combo"):
                panel.ev_combo.currentIndexChanged.connect(self._on_child_combo_changed)

        pages = [
            self._page_dashboard(),  # index 0
            self.evidence_panel,     # index 1
            self.analysis_panel,     # index 2
            self.ioc_panel,          # index 3
            self.timeline_panel,     # index 4
            self.attack_panel,       # index 5
            self.profile_panel,      # index 6
            self.geo_panel,          # index 7
            self.report_panel,       # index 8
        ]
        for page in pages:
            self.stack.addWidget(page)
        return self.stack

    # ── Dashboard Page ────────────────────────────────────────────────────────

    def _page_dashboard(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(10)

        title = QLabel("CASE OVERVIEW")
        title.setStyleSheet(
            "color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;"
        )
        outer.addWidget(title)

        self.dash_sub = QLabel("// Start by going to Evidence \u2192 Intake to load your artifacts")
        self.dash_sub.setStyleSheet("color:#3d5068;font-size:11px;margin-bottom:4px;")
        
        # Evidence Filter Combo
        ev_row = QHBoxLayout()
        ev_lbl = QLabel("Filter:")
        ev_lbl.setStyleSheet("color:#3d5068;font-size:11px;font-family:Consolas;")
        self.dash_ev_combo = QComboBox()
        self.dash_ev_combo.setStyleSheet(
            "QComboBox{background:#080b0f;border:1px solid #1c2736;border-radius:4px;"
            "color:#cdd6e3;font-family:Consolas;font-size:11px;padding:4px 8px;}"
            "QComboBox::drop-down{border:none;}"
        )
        self.dash_ev_combo.addItem("All Evidence")
        self.dash_ev_combo.currentIndexChanged.connect(self._on_dash_ev_combo_changed)
        ev_row.addWidget(ev_lbl)
        ev_row.addWidget(self.dash_ev_combo)
        ev_row.addStretch()

        outer.addWidget(self.dash_sub)
        outer.addLayout(ev_row)

        # Scrollable content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(
            "QScrollArea{border:none;background:transparent;}"
            "QScrollBar:vertical{background:#0d1117;width:8px;}"
            "QScrollBar::handle:vertical{background:#1c2736;border-radius:4px;}"
            "QScrollBar::handle:vertical:hover{background:#253345;}"
        )
        content = QWidget()
        content.setStyleSheet("background:transparent;")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(0, 4, 0, 8)
        cl.setSpacing(14)

        # ── Live Stat Chips ───────────────────────────────────────────────────
        stats = QWidget()
        stats.setStyleSheet("background:transparent;")
        sl = QHBoxLayout(stats)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(12)

        self.dash_chips = {}
        chip_defs = [
            ("risk",      "—",  "RISK SCORE",      "#ff3d5a"),
            ("iocs",      "0",  "IOCs FOUND",       "#ffb020"),
            ("ttps",      "0",  "ATT&CK TTPs",      "#00c8ff"),
            ("artifacts", "0",  "ARTIFACTS",        "#00ff9d"),
            ("events",    "0",  "TIMELINE EVENTS",  "#a78bfa"),
        ]
        for key, val, lbl, color in chip_defs:
            chip = QFrame()
            chip.setStyleSheet(
                "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
            )
            chip_l = QVBoxLayout(chip)
            chip_l.setContentsMargins(16, 14, 16, 14)
            vl = QLabel(val)
            vl.setStyleSheet(
                f"color:{color};font-size:32px;font-weight:bold;font-family:Consolas;"
            )
            ll = QLabel(lbl)
            ll.setStyleSheet(
                "color:#3d5068;font-size:9px;letter-spacing:1px;font-family:Consolas;"
            )
            chip_l.addWidget(vl)
            chip_l.addWidget(ll)
            sl.addWidget(chip)
            self.dash_chips[key] = vl

        cl.addWidget(stats)

        # ── Case Info + Workflow cards row ────────────────────────────────────
        row2 = QWidget()
        row2.setStyleSheet("background:transparent;")
        rl2 = QHBoxLayout(row2)
        rl2.setContentsMargins(0, 0, 0, 0)
        rl2.setSpacing(12)

        # Case info card
        case_card = QFrame()
        case_card.setStyleSheet(
            "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
        )
        cc_l = QVBoxLayout(case_card)
        cc_l.setContentsMargins(20, 16, 20, 16)
        cc_l.setSpacing(6)
        cc_title = QLabel("// ACTIVE CASE")
        cc_title.setStyleSheet(
            "color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;"
        )
        cc_l.addWidget(cc_title)

        self.dash_case_labels = {}
        for field, default in [
            ("Case ID",   "—"),
            ("Analyst",   "—"),
            ("Device",    "—"),
            ("Case Type", "—"),
            ("Opened",    "—"),
        ]:
            row = QHBoxLayout()
            row.setSpacing(8)
            key_lbl = QLabel(f"{field}:")
            key_lbl.setStyleSheet("color:#3d5068;font-size:11px;min-width:80px;")
            val_lbl = QLabel(default)
            val_lbl.setStyleSheet("color:#cdd6e3;font-size:11px;font-family:Consolas;")
            row.addWidget(key_lbl)
            row.addWidget(val_lbl, 1)
            cc_l.addLayout(row)
            self.dash_case_labels[field] = val_lbl

        cc_l.addStretch()
        rl2.addWidget(case_card, 1)

        # Workflow checklist card
        wf_card = QFrame()
        wf_card.setStyleSheet(
            "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
        )
        wf_l = QVBoxLayout(wf_card)
        wf_l.setContentsMargins(20, 16, 20, 16)
        wf_l.setSpacing(6)
        wf_title = QLabel("// INVESTIGATION WORKFLOW")
        wf_title.setStyleSheet(
            "color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;"
        )
        wf_l.addWidget(wf_title)

        self.dash_workflow = {}
        steps = [
            ("evidence",   "Evidence → Intake"),
            ("analysis",   "AI Analysis"),
            ("ioc",        "IOC Registry"),
            ("timeline",   "Reconstruction"),
            ("attack",     "ATT&CK Map"),
            ("profile",    "Attacker Profile"),
            ("geo",        "Geo Map"),
            ("report",     "Auto Report"),
        ]
        for key, name in steps:
            step_lbl = QLabel(f"  ○  {name}")
            step_lbl.setStyleSheet(
                "color:#3d5068;font-size:11px;font-family:Consolas;"
            )
            wf_l.addWidget(step_lbl)
            self.dash_workflow[key] = step_lbl

        wf_l.addStretch()
        rl2.addWidget(wf_card, 1)
        cl.addWidget(row2)

        # ── Activity Log ──────────────────────────────────────────────────────
        log_card = QFrame()
        log_card.setStyleSheet(
            "QFrame{background:#0d1117;border:1px solid #1c2736;border-radius:6px;}"
        )
        log_l = QVBoxLayout(log_card)
        log_l.setContentsMargins(16, 12, 16, 12)
        log_l.setSpacing(6)
        log_title = QLabel("// ACTIVITY LOG")
        log_title.setStyleSheet(
            "color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;"
        )
        log_l.addWidget(log_title)

        self.dash_log = QTextEdit()
        self.dash_log.setReadOnly(True)
        self.dash_log.setFixedHeight(160)
        self.dash_log.setStyleSheet(
            "QTextEdit{background:#080b0f;border:1px solid #1c2736;"
            "color:#6b7f96;font-family:Consolas;font-size:11px;padding:8px;}"
        )
        self.dash_log.setPlaceholderText(
            "Activity will appear here as you load evidence and run analysis..."
        )
        log_l.addWidget(self.dash_log)
        cl.addWidget(log_card)
        cl.addStretch()

        scroll.setWidget(content)
        outer.addWidget(scroll)
        return page

    # ── Live Update Methods ───────────────────────────────────────────────────

    def _on_child_combo_changed(self):
        combo = self.sender()
        if combo:
            target_name = "All Evidence"
            idx = combo.currentIndex()
            if hasattr(self.evidence_panel, "evidence_items") and idx > 0 and (idx - 1) < len(self.evidence_panel.evidence_items):
                target_name = self.evidence_panel.evidence_items[idx - 1].get("name")
            self.global_state.set_active_evidence(target_name)

    def _on_dash_ev_combo_changed(self):
        target_name = "All Evidence"
        idx = self.dash_ev_combo.currentIndex()
        if hasattr(self.evidence_panel, "evidence_items") and idx > 0 and (idx - 1) < len(self.evidence_panel.evidence_items):
            target_name = self.evidence_panel.evidence_items[idx - 1].get("name")
        self.global_state.set_active_evidence(target_name)

    def _update_dashboard(self, *_):
        """Refresh all dashboard chips + case info from live panel data."""
        
        # Determine target evidence
        target_name = None
        idx = self.dash_ev_combo.currentIndex()
        if hasattr(self.evidence_panel, "evidence_items") and idx > 0 and (idx - 1) < len(self.evidence_panel.evidence_items):
            target_name = self.evidence_panel.evidence_items[idx - 1].get("name")

        # Basic sets
        all_ev    = self.evidence_panel.evidence_items if hasattr(self.evidence_panel, "evidence_items") else []
        all_iocs  = self.ioc_panel.get_iocs()             if hasattr(self.ioc_panel, "get_iocs") else []
        all_events= self.timeline_panel.events            if hasattr(self.timeline_panel, "events") else []
        all_ttps  = self.attack_panel.get_detected()      if hasattr(self.attack_panel, "get_detected") else []

        n_ev      = len(all_ev)
        
        n_iocs    = len([i for i in all_iocs if not target_name or i.get("source") == target_name])
        n_events  = len([e for e in all_events if not target_name or e.get("source") == target_name])
        n_ttps    = len(all_ttps) # TTPs are global in memory currently

        # Risk formula: each IOC = 2 pts, each TTP = 5 pts, each event = 1 pt (max 100)
        risk_raw = min(100, n_iocs * 2 + n_ttps * 5 + n_events)
        risk_str = f"{risk_raw}" if (risk_raw > 0) else "\u2014"

        self.dash_chips["risk"].setText(risk_str)
        self.dash_chips["iocs"].setText(str(n_iocs))
        self.dash_chips["ttps"].setText(str(n_ttps))
        if target_name:
            self.dash_chips["artifacts"].setText("1")
        else:
            self.dash_chips["artifacts"].setText(str(n_ev))
        self.dash_chips["events"].setText(str(n_events))

        # Colour-code risk chip
        risk_color = "#ff3d5a" if risk_raw >= 60 else ("#ffb020" if risk_raw >= 30 else "#00ff9d")
        self.dash_chips["risk"].setStyleSheet(
            f"color:{risk_color};font-size:32px;font-weight:bold;font-family:Consolas;"
        )

        # Case info fields
        if hasattr(self.evidence_panel, "get_case_info"):
            case = self.evidence_panel.get_case_info()
            self.dash_case_labels["Case ID"].setText(case.get("case_id", "\u2014"))
            self.dash_case_labels["Analyst"].setText(case.get("analyst",  "\u2014"))
            self.dash_case_labels["Device"].setText(case.get("device",   "\u2014"))
            self.dash_case_labels["Case Type"].setText(case.get("type", "\u2014"))

        # Sub-heading
        if n_ev > 0:
            if target_name:
                self.dash_sub.setText(f"// Filtering scope: {target_name} \u2014 {n_iocs} IOCs  \u00b7  {n_events} events")
            else:
                self.dash_sub.setText(
                    f"// {n_ev} artifact{'s' if n_ev>1 else ''} loaded"
                    f" \u2014 {n_iocs} IOCs  \u00b7  {n_ttps} TTPs  \u00b7  {n_events} events"
                )
        else:
            self.dash_sub.setText(
                "// Start by going to Evidence \u2192 Intake to load your artifacts"
            )

        # Workflow checklist \u2014 mark steps with data as complete
        ioc_done = getattr(self.ioc_panel, "has_run", False) or n_iocs > 0
        tl_done  = getattr(self.timeline_panel, "has_run", False) or n_events > 0
        atk_done = getattr(self.attack_panel, "has_run", False) or n_ttps > 0

        states = {
            "evidence": n_ev > 0,
            "analysis": ioc_done or tl_done or atk_done,
            "ioc":      ioc_done,
            "timeline": tl_done,
            "attack":   atk_done,
            "profile":  getattr(self.profile_panel, "has_run", False),
            "geo":      getattr(self.geo_panel, "has_run", False),
            "report":   n_ev > 0,
        }
        for key, done in states.items():
            lbl   = self.dash_workflow[key]
            name  = lbl.text()[5:]          # strip "  ○  " or "  ●  "
            mark  = "●" if done else "○"
            color = "#00ff9d" if done else "#3d5068"
            lbl.setText(f"  {mark}  {name}")
            lbl.setStyleSheet(f"color:{color};font-size:11px;font-family:Consolas;")

        # Sidebar case info
        self.case_info_label.setText(
            f"CASE: {self.dash_case_labels['Case ID'].text()}\n"
            f"ANALYST: {self.dash_case_labels['Analyst'].text()}\n"
            f"EVIDENCE: {n_ev}\n"
            f"IOCs: {n_iocs}\n"
            f"RISK: {risk_str}"
        )

    def _log_activity(self, message: str):
        """Append a timestamped message to the activity log."""
        ts  = datetime.now(timezone.utc).strftime("%H:%M:%S")
        cur = self.dash_log.toPlainText()
        self.dash_log.setPlainText(f"[{ts}] {message}\n{cur}")

    # ── Navigation ────────────────────────────────────────────────────────────

    def _switch_page(self, page_index, clicked_btn):
        for btn, _ in self.nav_buttons:
            btn.setChecked(False)
        clicked_btn.setChecked(True)
        self.stack.setCurrentIndex(page_index)

        # Always refresh dashboard when returning to it
        if page_index == 0:
            self._update_dashboard()
        # Sync report panel when opened
        if page_index == 8:
            self._sync_report_panel()

    # ── Signal Handlers ───────────────────────────────────────────────────────

    def _on_evidence_updated(self, items):
        """Called every time evidence is added / updated in Evidence Intake."""
        self.analysis_panel.set_evidence(items)
        self.ioc_panel.set_evidence(items)
        self.timeline_panel.set_evidence(items)
        self.attack_panel.set_evidence(items)
        self.profile_panel.set_evidence(items)
        self.geo_panel.set_evidence(items)
        self.geo_panel.set_iocs(self.ioc_panel.get_iocs())

        self.dash_ev_combo.blockSignals(True)
        self.dash_ev_combo.clear()
        self.dash_ev_combo.addItem("All Evidence")
        for item in items:
            self.dash_ev_combo.addItem(f"{item['id']}: {item['name']}")
        self.dash_ev_combo.blockSignals(False)

        self._update_dashboard()

        if items:
            latest = items[-1]
            self._log_activity(
                f"Evidence added: {latest.get('name','?')}  "
                f"({latest.get('size_str','?')})"
            )

    def _on_global_evidence_changed(self, evidence_name: str):
        """Handle centralized evidence scope switching."""
        self._log_activity(f"Scope switched to: {evidence_name}")
        
        # Determine index for sync
        idx = 0
        if evidence_name != "All Evidence":
            ev_list = self.evidence_panel.evidence_items if hasattr(self.evidence_panel, "evidence_items") else []
            for i, e in enumerate(ev_list):
                if e.get("name") == evidence_name:
                    idx = i + 1
                    break
                    
        # Sync combos
        combos = [self.dash_ev_combo]
        if hasattr(self.ioc_panel, "ev_combo"):
            combos.append(self.ioc_panel.ev_combo)
        if hasattr(self.timeline_panel, "ev_combo"):
            combos.append(self.timeline_panel.ev_combo)
        if hasattr(self.attack_panel, "ev_combo"):
            combos.append(self.attack_panel.ev_combo)
        if hasattr(self.report_panel, "ev_combo"):
            combos.append(self.report_panel.ev_combo)
            
        for cb in combos:
            cb.blockSignals(True)
            if cb.count() > idx:
                cb.setCurrentIndex(idx)
            cb.blockSignals(False)

        # Clear stale panel data
        if hasattr(self.ioc_panel, "clear_data"):      self.ioc_panel.clear_data()
        if hasattr(self.timeline_panel, "clear_data"): self.timeline_panel.clear_data()
        if hasattr(self.attack_panel, "clear_data"):   self.attack_panel.clear_data()
        
        self._update_dashboard()
        self._sync_report_panel()

    def _sync_report_panel(self):
        case = self.evidence_panel.get_case_info() \
               if hasattr(self.evidence_panel, "get_case_info") else {}
               
        n_iocs   = len(self.ioc_panel.get_iocs())
        n_ttps   = len(self.attack_panel.get_detected()) if hasattr(self.attack_panel, "get_detected") else 0
        n_events = len(self.timeline_panel.events) if hasattr(self.timeline_panel, "events") else 0
        calc_risk = min(100, n_iocs * 2 + n_ttps * 5 + n_events)

        self.report_panel.update_case_data({
            "case_id":           case.get("case_id",  "Unassigned"),
            "analyst":           case.get("analyst",  "Unknown"),
            "device":            case.get("device",   "Unknown"),
            "case_type":         case.get("type",     "Unknown"),
            "evidence":          self.evidence_panel.get_evidence()
                                 if hasattr(self.evidence_panel, "get_evidence") else [],
            "iocs":              self.ioc_panel.get_iocs(),
            "timeline":          self.timeline_panel.events
                                 if hasattr(self.timeline_panel, "events") else [],
            "attack_techniques": self.attack_panel.get_detected()
                                 if hasattr(self.attack_panel, "get_detected") else {},
            "custody_log":       self.evidence_panel.custody_log
                                 if hasattr(self.evidence_panel, "custody_log") else [],
            "risk_score":        calc_risk,
        })

    # ── Clock ─────────────────────────────────────────────────────────────────

    def _start_clock(self):
        self._update_clock()
        t = QTimer(self)
        t.timeout.connect(self._update_clock)
        t.start(1000)

    def _update_clock(self):
        self.clock_label.setText(
            datetime.now(timezone.utc).strftime("%Y-%m-%d  %H:%M:%S UTC")
        )