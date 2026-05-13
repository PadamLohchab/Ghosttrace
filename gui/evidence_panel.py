"""
SPECTR / GhostTrace — Evidence Intake Panel
Handles file loading, hashing, and chain of custody logging.
"""

import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QFileDialog, QLineEdit, QComboBox, QTextEdit,
    QScrollArea, QGridLayout, QProgressBar, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent


CARD_STYLE = """
    QFrame {
        background: #0d1117;
        border: 1px solid #1c2736;
        border-radius: 6px;
    }
"""

INPUT_STYLE = """
    QLineEdit, QComboBox {
        background: #080b0f;
        border: 1px solid #1c2736;
        border-radius: 4px;
        color: #cdd6e3;
        font-family: Consolas;
        font-size: 12px;
        padding: 6px 10px;
        min-height: 28px;
    }
    QLineEdit:focus, QComboBox:focus {
        border-color: #00c8ff;
    }
    QComboBox::drop-down { border: none; }
    QComboBox QAbstractItemView {
        background: #0d1117;
        color: #cdd6e3;
        border: 1px solid #1c2736;
        selection-background-color: #111820;
    }
"""

BTN_PRIMARY = """
    QPushButton {
        background: rgba(0,200,255,0.1);
        border: 1px solid #00c8ff;
        border-radius: 4px;
        color: #00c8ff;
        font-family: Consolas;
        font-size: 12px;
        padding: 8px 18px;
    }
    QPushButton:hover { background: rgba(0,200,255,0.2); }
    QPushButton:pressed { background: rgba(0,200,255,0.3); }
"""

BTN_NORMAL = """
    QPushButton {
        background: transparent;
        border: 1px solid #1c2736;
        border-radius: 4px;
        color: #6b7f96;
        font-family: Consolas;
        font-size: 12px;
        padding: 8px 18px;
    }
    QPushButton:hover { background: #111820; color: #cdd6e3; border-color: #253345; }
"""


class HashWorker(QThread):
    """Computes hashes in background thread — safe for large files."""
    finished = pyqtSignal(dict)
    progress  = pyqtSignal(int)

    def __init__(self, file_path: str):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            md5    = hashlib.md5()
            sha1   = hashlib.sha1()
            sha256 = hashlib.sha256()
            size   = os.path.getsize(self.file_path)
            done   = 0
            chunk  = 65536

            with open(self.file_path, "rb") as f:
                while data := f.read(chunk):
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)
                    done += len(data)
                    if size > 0:
                        self.progress.emit(int(done / size * 100))

            self.finished.emit({
                "md5":    md5.hexdigest(),
                "sha1":   sha1.hexdigest(),
                "sha256": sha256.hexdigest(),
            })
        except Exception as e:
            self.finished.emit({"error": str(e)})


class DropZone(QFrame):
    """Drag and drop file zone."""
    files_dropped = pyqtSignal(list)

    def __init__(self, label: str, extensions: str):
        super().__init__()
        self.setAcceptDrops(True)
        self.setMinimumHeight(110)
        self._set_style(False)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.icon_lbl = QLabel("⬇")
        self.icon_lbl.setStyleSheet("color: #1c2736; font-size: 28px;")
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.icon_lbl)

        self.main_lbl = QLabel(label)
        self.main_lbl.setStyleSheet("color: #3d5068; font-size: 12px; font-family: Consolas;")
        self.main_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.main_lbl)

        ext_lbl = QLabel(extensions)
        ext_lbl.setStyleSheet("color: #253345; font-size: 10px; font-family: Consolas;")
        ext_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(ext_lbl)

    def _set_style(self, active: bool):
        if active:
            self.setStyleSheet("""
                QFrame {
                    background: rgba(0,200,255,0.05);
                    border: 1px dashed #00c8ff;
                    border-radius: 6px;
                }
            """)
        else:
            self.setStyleSheet("""
                QFrame {
                    background: #080b0f;
                    border: 1px dashed #1c2736;
                    border-radius: 6px;
                }
            """)

    def dragEnterEvent(self, e: QDragEnterEvent):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._set_style(True)

    def dragLeaveEvent(self, e):
        self._set_style(False)

    def dropEvent(self, e: QDropEvent):
        self._set_style(False)
        paths = [u.toLocalFile() for u in e.mimeData().urls()]
        self.files_dropped.emit(paths)


class EvidenceCard(QFrame):
    """Displays one evidence item with hashes."""

    def __init__(self, item: dict):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background: #111820;
                border: 1px solid #1c2736;
                border-radius: 4px;
            }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        # Top row
        top = QHBoxLayout()
        badge_colors = {
            "disk":   ("#00c8ff", "rgba(0,200,255,0.15)"),
            "memory": ("#ff3d5a", "rgba(255,61,90,0.15)"),
            "log":    ("#00ff9d", "rgba(0,255,157,0.1)"),
            "pcap":   ("#ffb020", "rgba(255,176,32,0.15)"),
            "other":  ("#a78bfa", "rgba(167,139,250,0.15)"),
        }
        fc, bc = badge_colors.get(item.get("type","other"), badge_colors["other"])

        badge = QLabel(item.get("type","?").upper())
        badge.setStyleSheet(f"color:{fc};background:{bc};border-radius:3px;padding:2px 7px;font-size:10px;font-family:Consolas;font-weight:bold;")

        ev_id = QLabel(item.get("id","—"))
        ev_id.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")

        name = QLabel(item.get("name","—"))
        name.setStyleSheet("color:#cdd6e3;font-size:12px;font-family:Consolas;")

        size = QLabel(item.get("size_str","—"))
        size.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")

        top.addWidget(badge)
        top.addWidget(ev_id)
        top.addWidget(name)
        top.addStretch()
        top.addWidget(size)
        layout.addLayout(top)

        # Hash rows
        for alg, val in [
            ("MD5",    item.get("md5","computing...")),
            ("SHA-1",  item.get("sha1","computing...")),
            ("SHA-256",item.get("sha256","computing...")),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(alg)
            lbl.setFixedWidth(52)
            lbl.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
            val_lbl = QLabel(val)
            val_lbl.setStyleSheet("color:#00ff9d;font-size:10px;font-family:Consolas;")
            val_lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            row.addWidget(lbl)
            row.addWidget(val_lbl)
            layout.addLayout(row)

        ts = QLabel(f"Added: {item.get('added_at','—')}")
        ts.setStyleSheet("color:#253345;font-size:10px;font-family:Consolas;margin-top:2px;")
        layout.addWidget(ts)


class EvidencePanel(QWidget):
    """Full evidence intake panel."""

    # Signal emitted when evidence list changes — main window listens
    evidence_updated = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.evidence_items = []
        self.custody_log    = []
        self.hash_workers   = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(14)

        # Title
        title = QLabel("EVIDENCE INTAKE")
        title.setStyleSheet("color:#cdd6e3;font-size:22px;font-weight:bold;letter-spacing:3px;")
        layout.addWidget(title)

        sub = QLabel("// Load artifacts — hashes computed automatically — chain of custody logged")
        sub.setStyleSheet("color:#3d5068;font-size:11px;margin-bottom:4px;")
        layout.addWidget(sub)

        # Scroll area for all content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:none;background:transparent;}")

        content = QWidget()
        content.setStyleSheet("background:transparent;")
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(14)
        content_layout.setContentsMargins(0,0,0,0)

        # ── Case metadata ──
        meta_frame = QFrame()
        meta_frame.setStyleSheet(CARD_STYLE)
        meta_layout = QVBoxLayout(meta_frame)
        meta_layout.setContentsMargins(16,14,16,14)
        meta_layout.setSpacing(8)

        meta_title = QLabel("// CASE METADATA")
        meta_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        meta_layout.addWidget(meta_title)

        grid = QGridLayout()
        grid.setSpacing(8)

        self.case_id_input    = QLineEdit(); self.case_id_input.setPlaceholderText("Case ID (e.g. DF-2025-001)")
        self.analyst_input    = QLineEdit(); self.analyst_input.setPlaceholderText("Analyst name")
        self.device_input     = QLineEdit(); self.device_input.setPlaceholderText("Device description (e.g. WD 1TB HDD — jsmith-laptop)")
        self.case_type_combo  = QComboBox()
        self.case_type_combo.addItems(["-- Case Type --","Malware Incident","Data Exfiltration","Insider Threat","Ransomware","Unauthorized Access","Other"])

        for w in [self.case_id_input, self.analyst_input, self.device_input, self.case_type_combo]:
            w.setStyleSheet(INPUT_STYLE)

        grid.addWidget(QLabel("Case ID:"),   0, 0); grid.addWidget(self.case_id_input,   0, 1)
        grid.addWidget(QLabel("Analyst:"),   0, 2); grid.addWidget(self.analyst_input,   0, 3)
        grid.addWidget(QLabel("Device:"),    1, 0); grid.addWidget(self.device_input,    1, 1)
        grid.addWidget(QLabel("Type:"),      1, 2); grid.addWidget(self.case_type_combo, 1, 3)

        for i in range(grid.count()):
            w = grid.itemAt(i).widget()
            if isinstance(w, QLabel):
                w.setStyleSheet("color:#6b7f96;font-size:11px;font-family:Consolas;")

        meta_layout.addLayout(grid)

        save_btn = QPushButton("Save Case Info")
        save_btn.setStyleSheet(BTN_PRIMARY)
        save_btn.setFixedWidth(140)
        save_btn.clicked.connect(self._save_case)
        meta_layout.addWidget(save_btn)

        content_layout.addWidget(meta_frame)

        # ── Drop zones ──
        zones_frame = QFrame()
        zones_frame.setStyleSheet(CARD_STYLE)
        zones_layout = QVBoxLayout(zones_frame)
        zones_layout.setContentsMargins(16,14,16,14)
        zones_layout.setSpacing(10)

        zt = QLabel("// LOAD ARTIFACTS")
        zt.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        zones_layout.addWidget(zt)

        zones_row = QHBoxLayout()
        zones_row.setSpacing(10)

        self.disk_zone = DropZone("Drop Disk / Memory Images", ".dd  .img  .raw  .e01  .vmem  .dmp")
        self.log_zone  = DropZone("Drop Logs / PCAP / Registry", ".log  .evtx  .txt  .pcap  .pcapng  .csv")

        self.disk_zone.files_dropped.connect(lambda p: self._load_files(p, "disk"))
        self.log_zone.files_dropped.connect(lambda p: self._load_files(p, "log"))

        zones_row.addWidget(self.disk_zone)
        zones_row.addWidget(self.log_zone)
        zones_layout.addLayout(zones_row)

        # Browse buttons
        btn_row = QHBoxLayout()
        browse_disk = QPushButton("Browse Disk / Memory")
        browse_log  = QPushButton("Browse Logs / PCAP")
        browse_disk.setStyleSheet(BTN_NORMAL)
        browse_log.setStyleSheet(BTN_NORMAL)
        browse_disk.clicked.connect(lambda: self._browse("disk"))
        browse_log.clicked.connect(lambda: self._browse("log"))
        btn_row.addWidget(browse_disk)
        btn_row.addWidget(browse_log)
        btn_row.addStretch()
        zones_layout.addLayout(btn_row)

        content_layout.addWidget(zones_frame)

        # ── Evidence list ──
        ev_frame = QFrame()
        ev_frame.setStyleSheet(CARD_STYLE)
        ev_layout = QVBoxLayout(ev_frame)
        ev_layout.setContentsMargins(16,14,16,14)
        ev_layout.setSpacing(8)

        ev_header = QHBoxLayout()
        ev_title = QLabel("// EVIDENCE ITEMS")
        ev_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;")
        self.ev_count = QLabel("0 items")
        self.ev_count.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;")
        ev_header.addWidget(ev_title)
        ev_header.addStretch()
        ev_header.addWidget(self.ev_count)
        ev_layout.addLayout(ev_header)

        self.ev_list_layout = QVBoxLayout()
        self.ev_list_layout.setSpacing(6)

        empty_lbl = QLabel("No evidence loaded yet.")
        empty_lbl.setStyleSheet("color:#253345;font-size:12px;font-family:Consolas;padding:16px;")
        empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ev_list_layout.addWidget(empty_lbl)
        self.empty_label = empty_lbl

        ev_layout.addLayout(self.ev_list_layout)
        content_layout.addWidget(ev_frame)

        # ── Custody log ──
        coc_frame = QFrame()
        coc_frame.setStyleSheet(CARD_STYLE)
        coc_layout = QVBoxLayout(coc_frame)
        coc_layout.setContentsMargins(16,14,16,14)

        coc_title = QLabel("// CHAIN OF CUSTODY LOG")
        coc_title.setStyleSheet("color:#3d5068;font-size:10px;font-family:Consolas;letter-spacing:2px;margin-bottom:6px;")
        coc_layout.addWidget(coc_title)

        self.coc_text = QTextEdit()
        self.coc_text.setReadOnly(True)
        self.coc_text.setFixedHeight(140)
        self.coc_text.setStyleSheet("""
            QTextEdit {
                background: #080b0f;
                border: 1px solid #1c2736;
                border-radius: 4px;
                color: #6b7f96;
                font-family: Consolas;
                font-size: 11px;
                padding: 8px;
            }
        """)
        self.coc_text.setPlaceholderText("Chain of custody entries will appear here...")
        coc_layout.addWidget(self.coc_text)

        export_btn = QPushButton("Export Custody Log")
        export_btn.setStyleSheet(BTN_NORMAL)
        export_btn.setFixedWidth(160)
        export_btn.clicked.connect(self._export_custody)
        coc_layout.addWidget(export_btn)

        content_layout.addWidget(coc_frame)
        content_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)

        self._log_custody("Session Started", "System", "N/A", "GhostTrace session initialized")

    def _save_case(self):
        case_id = self.case_id_input.text().strip()
        analyst = self.analyst_input.text().strip()
        if not case_id or not analyst:
            QMessageBox.warning(self, "Missing Info", "Please enter Case ID and Analyst name.")
            return
        self._log_custody("Case Created", analyst, case_id, f"Case initialized — Type: {self.case_type_combo.currentText()}")
        QMessageBox.information(self, "Saved", f"Case {case_id} saved successfully.")

    def _browse(self, file_type: str):
        if file_type == "disk":
            filters = "Disk/Memory Images (*.dd *.img *.raw *.e01 *.vmem *.dmp *.mem);;All Files (*)"
        else:
            filters = "Evidence Files (*.log *.evtx *.txt *.pcap *.pcapng *.csv *.reg);;All Files (*)"

        paths, _ = QFileDialog.getOpenFileNames(self, "Select Evidence Files", "", filters)
        if paths:
            self._load_files(paths, file_type)

    def _load_files(self, paths: list, file_type: str):
        for path in paths:
            if not os.path.exists(path):
                continue
            self._add_evidence(path, file_type)

    def _guess_type(self, name: str, default: str) -> str:
        n = name.lower()
        if any(n.endswith(e) for e in [".dd",".img",".raw",".e01",".vmem",".vhd",".vmdk"]):
            return "disk"
        if any(n.endswith(e) for e in [".dmp",".mem",".vmem"]):
            return "memory"
        if any(n.endswith(e) for e in [".pcap",".pcapng",".cap"]):
            return "pcap"
        if any(n.endswith(e) for e in [".log",".evtx",".txt",".csv",".reg"]):
            return "log"
        return default

    def _fmt_size(self, b: int) -> str:
        for u in ["B","KB","MB","GB","TB"]:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} PB"

    def _add_evidence(self, path: str, file_type: str):
        name     = os.path.basename(path)
        size     = os.path.getsize(path)
        ev_type  = self._guess_type(name, file_type)
        ev_id    = f"EV-{len(self.evidence_items)+1:03d}"
        added_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        item = {
            "id":       ev_id,
            "name":     name,
            "path":     path,
            "type":     ev_type,
            "size":     size,
            "size_str": self._fmt_size(size),
            "added_at": added_at,
            "md5":      "computing...",
            "sha1":     "computing...",
            "sha256":   "computing...",
            "content":  "",
        }

        # Try to read text content for AI analysis
        try:
            with open(path, "r", errors="replace") as f:
                item["content"] = f.read(50000)
        except Exception:
            item["content"] = "[binary file]"

        self.evidence_items.append(item)
        self._render_evidence()
        self._log_custody("Evidence Added", self.analyst_input.text() or "Analyst", name,
                          f"{ev_type.upper()} artifact loaded — {self._fmt_size(size)}")

        # Start hashing in background
        worker = HashWorker(path)
        worker.finished.connect(lambda hashes, i=item: self._on_hashed(hashes, i))
        worker.start()
        self.hash_workers.append(worker)

    def _on_hashed(self, hashes: dict, item: dict):
        if "error" in hashes:
            return
        item["md5"]    = hashes.get("md5","—")
        item["sha1"]   = hashes.get("sha1","—")
        item["sha256"] = hashes.get("sha256","—")
        self._render_evidence()
        self._log_custody("Hash Computed", "System", item["name"],
                          f"MD5: {item['md5'][:16]}... SHA256: {item['sha256'][:16]}...")
        self.evidence_updated.emit(self.evidence_items)

    def _render_evidence(self):
        # Clear list
        while self.ev_list_layout.count():
            w = self.ev_list_layout.takeAt(0).widget()
            if w: w.deleteLater()

        if not self.evidence_items:
            lbl = QLabel("No evidence loaded yet.")
            lbl.setStyleSheet("color:#253345;font-size:12px;font-family:Consolas;padding:16px;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ev_list_layout.addWidget(lbl)
        else:
            for item in self.evidence_items:
                card = EvidenceCard(item)
                self.ev_list_layout.addWidget(card)

        self.ev_count.setText(f"{len(self.evidence_items)} item(s)")

    def _log_custody(self, action: str, analyst: str, evidence: str, notes: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        entry = f"[{ts}] {action} | {analyst} | {evidence} | {notes}"
        self.custody_log.append(entry)
        self.coc_text.append(entry)

    def _export_custody(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Custody Log", "custody_log.txt", "Text Files (*.txt)")
        if path:
            with open(path, "w") as f:
                f.write("\n".join(self.custody_log))
            QMessageBox.information(self, "Exported", f"Custody log saved to {path}")

    def get_evidence(self) -> list:
        return self.evidence_items

    def get_case_info(self) -> dict:
        return {
            "case_id": self.case_id_input.text().strip(),
            "analyst": self.analyst_input.text().strip(),
            "device":  self.device_input.text().strip(),
            "type":    self.case_type_combo.currentText(),
        }
