# 👻 GhostTrace — Advanced Dead System Forensics & Timeline Reconstruction Framework

GhostTrace is an advanced dead-system digital forensics framework developed using Python and PyQt6 for performing offline forensic investigations on compromised or suspicious systems. The framework is designed to automate forensic artifact collection, event correlation, timeline reconstruction, and suspicious activity analysis through a centralized graphical investigation environment.

GhostTrace enables investigators to analyze forensic evidence extracted from offline systems and reconstruct chronological system activity by correlating timestamps and metadata from multiple forensic artifacts. The framework assists in identifying indicators of compromise, suspicious executable activity, persistence mechanisms, user actions, and post-compromise behavior during digital forensic investigations.

The tool performs forensic analysis on multiple Windows-based artifacts including Event Logs (EVTX), NTFS timestamps, Prefetch files, browser history artifacts, startup persistence entries, USB device history, shortcut files, deleted file metadata, and recently accessed files. By parsing and correlating these artifacts, GhostTrace reconstructs system activity timelines and provides investigators with a structured view of attack progression and user behavior.

GhostTrace includes a GUI-based forensic investigation dashboard that allows investigators to visualize parsed artifacts, analyze suspicious events, inspect timeline activity, and generate forensic investigation reports. The framework is designed to simplify offline forensic analysis workflows while improving evidence visibility and investigation efficiency.

---

# 🚀 Core Features

* Dead-system forensic investigation
* Multi-artifact forensic analysis
* Windows Event Log (EVTX) parsing
* NTFS timestamp correlation
* Prefetch execution analysis
* Browser history investigation
* USB connection tracking
* Startup persistence analysis
* Shortcut artifact analysis
* Deleted file metadata inspection
* Suspicious activity detection
* Timeline reconstruction engine
* Artifact correlation system
* GUI-based forensic dashboard
* Automated forensic report generation

---

# 🧩 Forensic Artifacts Analyzed

### 🖥️ System Artifacts

* Windows Security Logs
* System & Application EVTX Logs
* Login and logout activity
* Service execution events
* Error and crash events

### 📂 File System Artifacts

* File creation timestamps
* File modification timestamps
* File access timestamps
* Deleted file traces
* Hidden executable analysis

### ⚙️ Execution & Persistence Artifacts

* Windows Prefetch files (`.pf`)
* Startup entries
* Scheduled task indicators
* Persistence mechanisms

### 🌐 User Activity Artifacts

* Browser history
* Download history
* Recently accessed files
* Shortcut (`.lnk`) artifacts
* USB device history

---

# 🕒 Timeline Reconstruction

GhostTrace reconstructs chronological forensic timelines by correlating timestamps collected from distributed forensic artifacts. The framework aggregates evidence from system logs, file metadata, execution traces, and user activity records to generate a unified investigation timeline.

The timeline reconstruction engine assists investigators in identifying:

* File execution sequences
* USB insertion activity
* Browser download events
* Suspicious executable launches
* File deletion attempts
* Persistence creation events
* User interaction timelines

---

# ⚙️ Technologies Used

* Python
* PyQt6
* SQLite
* JSON
* Windows Forensic Artifacts

---

# 📁 Project Structure

```text id="2p7cs9"
GhostTrace/
│
├── gui/
├── core/
├── utils/
├── sample_reports/
├── screenshots/
├── main.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

# ▶️ Installation & Execution

## Install Dependencies

```bash id="6f7r6t"
pip install -r requirements.txt
```

## Run Application

```bash id="44jlwm"
python main.py
```

---

# 🔬 Investigation Workflow

```text id="i3m4s6"
Load Artifacts
      ↓
Parse Evidence
      ↓
Correlate Events
      ↓
Reconstruct Timeline
      ↓
Detect Suspicious Activity
      ↓
Generate Forensic Report
```

---

# 📌 Use Cases

* Malware investigation
* Offline forensic analysis
* Incident response support
* User activity reconstruction
* Suspicious executable investigation
* Timeline-based forensic investigation
* Digital evidence analysis

---

# ⚠️ Disclaimer

This project is intended strictly for educational, research, and authorized digital forensic investigation purposes only.

---

#👨‍💻 Author
Padam

🎓 B.Tech — Computer Science Engineering (Cyber Security)
🔐 Digital Forensics & Cybersecurity Enthusiast
