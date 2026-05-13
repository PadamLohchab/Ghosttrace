import re
from datetime import datetime
from typing import List, Dict, Any

class LogParser:
    """
    GhostTrace — Universal Log Parser
    Extracts, normalizes, and chronological sorts mixed log formats.
    """

    def __init__(self):
        # 1. Multiple Regex Patterns
        # Syslog: e.g. "Oct 12 10:15:01" 
        # (Note: Syslog often lacks the year. We'll default to the current year.)
        self.syslog_pattern = re.compile(
            r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
        )
        
        # Apache/Web: e.g. "[12/Oct/2023:10:00:01 +0000]"
        self.apache_pattern = re.compile(
            r"\[(?P<datetime>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]"
        )
        
        # Standard/Windows: e.g. "2023-10-12 10:15:01"
        self.win_pattern = re.compile(
            r"^(?P<datetime>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
        )

        self.current_year = datetime.now().year

    def parse_line(self, line: str) -> Dict[str, Any]:
        """
        Attempts to parse a single log line using all available patterns.
        Returns a structured dictionary if a timestamp is found, or None.
        """
        line = line.strip()
        if not line:
            return None

        # Check Standard/Windows Format first
        match = self.win_pattern.search(line)
        if match:
            try:
                dt_str = match.group("datetime")
                dt_obj = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
                return {
                    'timestamp': dt_obj,
                    'original_line': line,
                    'source_type': 'win'
                }
            except ValueError:
                pass

        # Check Apache/Web Format
        match = self.apache_pattern.search(line)
        if match:
            try:
                dt_str = match.group("datetime")
                dt_obj = datetime.strptime(dt_str, "%d/%b/%Y:%H:%M:%S %z")
                # Strip timezone info for consistent naive comparison
                dt_obj = dt_obj.replace(tzinfo=None)
                return {
                    'timestamp': dt_obj,
                    'original_line': line,
                    'source_type': 'web'
                }
            except ValueError:
                pass

        # Check Syslog Format
        match = self.syslog_pattern.search(line)
        if match:
            try:
                m_str = match.group("month")
                d_str = match.group("day")
                t_str = match.group("time")
                # Syslog usually lacks a year, append the current year
                dt_str = f"{self.current_year} {m_str} {d_str} {t_str}"
                dt_obj = datetime.strptime(dt_str, "%Y %b %d %H:%M:%S")
                return {
                    'timestamp': dt_obj,
                    'original_line': line,
                    'source_type': 'syslog'
                }
            except ValueError:
                pass

        # Return None if no pattern matches
        return None

    def parse_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Reads a file line-by-line and parses formatting."""
        parsed_entries = []
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                entry = self.parse_line(line)
                if entry:
                    parsed_entries.append(entry)
        return parsed_entries

    def reconstruct_timeline(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Reconstruction Logic: Takes a list of parsed entries and sorts them 
        chronologically by the datetime object.
        """
        # Sort using the 'timestamp' key
        return sorted(entries, key=lambda x: x['timestamp'])

    def print_timeline(self, sorted_entries: List[Dict[str, Any]]):
        """Helper to cleanly print the chronological output."""
        print(f"{'TIMESTAMP':<25} | {'TYPE':<8} | {'ORIGINAL LINE'}")
        print("-" * 100)
        for entry in sorted_entries:
            ts = entry['timestamp'].strftime("%Y-%m-%d %H:%M:%S %Z").strip()
            print(f"{ts:<25} | {entry['source_type']:<8} | {entry['original_line'][:60]}...")

# ── Example Usage ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = LogParser()
    
    # Simulating a file containing mixed formats
    sample_logs = [
        "Oct 12 10:15:01 server sshd[123]: Accepted password for root",
        "[12/Oct/2023:10:00:01 +0000] 'GET /index.html HTTP/1.1' 200",
        "2023-10-12 10:10:01 INFO Application started successfully.",
        "Oct 12 09:15:01 system daemon restarted",  # Chronologically first
    ]
    
    parsed = []
    for line in sample_logs:
        result = parser.parse_line(line)
        if result:
            parsed.append(result)
            
    # Reconstruct chronological timeline
    timeline = parser.reconstruct_timeline(parsed)
    parser.print_timeline(timeline)
