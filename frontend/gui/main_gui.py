import sys
import os
import json
import html
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QTableWidget, QTableWidgetItem,
    QTabWidget, QLabel, QGroupBox, QComboBox, QFileDialog, QStatusBar,
    QSplitter, QHeaderView, QMessageBox, QAction, QDialog,
    QFormLayout, QDialogButtonBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor

import requests


# ── Config ──────────────────────────────────────────────────────────────────────

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")

DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
    "poll_interval_ms": 2000,
}


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# ── Async API Worker ────────────────────────────────────────────────────────────

class APIWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, method: str, url: str, data: dict = None):
        super().__init__()
        self.method = method
        self.url = url
        self.data = data

    def run(self):
        try:
            if self.method == "POST":
                resp = requests.post(self.url, json=self.data, timeout=10)
            else:
                resp = requests.get(self.url, timeout=10)
            resp.raise_for_status()
            self.finished.emit(resp.json())
        except Exception as e:
            self.error.emit(str(e))


# ── Config Dialog ───────────────────────────────────────────────────────────────

class ConfigDialog(QDialog):
    def __init__(self, config: dict, parent=None):
        super().__init__(parent)
        self.config = config.copy()
        self.setWindowTitle("Settings")
        self.setMinimumWidth(400)

        layout = QFormLayout(self)

        self.api_url_input = QLineEdit(self.config["api_url"])
        layout.addRow("API URL:", self.api_url_input)

        self.poll_input = QLineEdit(str(self.config["poll_interval_ms"]))
        layout.addRow("Poll Interval (ms):", self.poll_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def accept(self):
        self.config["api_url"] = self.api_url_input.text().strip()
        try:
            self.config["poll_interval_ms"] = int(self.poll_input.text())
        except ValueError:
            pass
        super().accept()


# ── Main Window ─────────────────────────────────────────────────────────────────

class AutoSecGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = load_config()
        self.current_task_id = None
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self._poll_task)
        self._workers: list[APIWorker] = []

        self.setWindowTitle("AutoSec Platform")
        self.setGeometry(100, 100, 1200, 750)
        self._build_menu()
        self._build_ui()
        self._apply_style()

    # ── Menu ────────────────────────────────────────────────────────────────────

    def _build_menu(self):
        menubar = self.menuBar()

        file_menu = menubar.addMenu("File")
        export_json = QAction("Export JSON Report", self)
        export_json.triggered.connect(lambda: self._export_report("json"))
        file_menu.addAction(export_json)

        export_html = QAction("Export HTML Report", self)
        export_html.triggered.connect(lambda: self._export_report("html"))
        file_menu.addAction(export_html)

        file_menu.addSeparator()
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        settings_menu = menubar.addMenu("Settings")
        config_action = QAction("API Configuration", self)
        config_action.triggered.connect(self._open_settings)
        settings_menu.addAction(config_action)

    # ── UI Layout ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # ── Top: Target Input ──
        input_group = QGroupBox("Target")
        input_layout = QHBoxLayout(input_group)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target URL or IP (e.g. http://example.com)")
        input_layout.addWidget(self.target_input, 1)

        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(["web", "cve", "intranet", "ad"])
        input_layout.addWidget(self.scan_type_combo)

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self._start_scan)
        input_layout.addWidget(self.scan_btn)

        self.ai_btn = QPushButton("Run AI Analysis")
        self.ai_btn.clicked.connect(self._run_ai)
        input_layout.addWidget(self.ai_btn)

        main_layout.addWidget(input_group)

        # ── Middle: Tabs ──
        splitter = QSplitter(Qt.Horizontal)

        # Left: Tabs (Vuln Table + Attack Paths)
        tabs = QTabWidget()

        # Vulnerability Table
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(5)
        self.vuln_table.setHorizontalHeaderLabels(["ID", "Name", "Type", "Severity", "Risk Score"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.vuln_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vuln_table.setAlternatingRowColors(True)
        tabs.addTab(self.vuln_table, "Vulnerabilities")

        # Attack Paths
        self.path_text = QTextEdit()
        self.path_text.setReadOnly(True)
        self.path_text.setFont(QFont("Consolas", 10))
        tabs.addTab(self.path_text, "Attack Paths")

        # Summary
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 10))
        tabs.addTab(self.summary_text, "Summary")

        splitter.addWidget(tabs)

        # Right: Log Window
        log_group = QGroupBox("Log")
        log_layout = QVBoxLayout(log_group)
        self.log_window = QTextEdit()
        self.log_window.setReadOnly(True)
        self.log_window.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_window)
        log_group.setMaximumWidth(350)

        splitter.addWidget(log_group)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)

        main_layout.addWidget(splitter, 1)

        # ── Bottom: Status Bar ──
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        self._log("AutoSec Platform started")
        self._log(f"API: {self.config['api_url']}")

    # ── Styling ─────────────────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow { background: #1e1e2e; }
            QGroupBox {
                color: #cdd6f4; font-weight: bold;
                border: 1px solid #45475a; border-radius: 6px;
                margin-top: 10px; padding-top: 14px;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }
            QLineEdit, QComboBox {
                background: #313244; color: #cdd6f4;
                border: 1px solid #45475a; border-radius: 4px;
                padding: 6px; font-size: 13px;
            }
            QPushButton {
                background: #89b4fa; color: #1e1e2e;
                border: none; border-radius: 4px;
                padding: 8px 16px; font-weight: bold; font-size: 13px;
            }
            QPushButton:hover { background: #74c7ec; }
            QPushButton:disabled { background: #585b70; color: #a6adc8; }
            QTableWidget {
                background: #1e1e2e; color: #cdd6f4;
                gridline-color: #45475a; font-size: 12px;
            }
            QHeaderView::section {
                background: #313244; color: #cdd6f4;
                padding: 6px; border: 1px solid #45475a;
                font-weight: bold;
            }
            QTableWidget::item:selected { background: #45475a; }
            QTextEdit {
                background: #181825; color: #a6e3a1;
                border: 1px solid #45475a; font-size: 12px;
            }
            QTabWidget::pane { border: 1px solid #45475a; background: #1e1e2e; }
            QTabBar::tab {
                background: #313244; color: #cdd6f4;
                padding: 8px 16px; border-top-left-radius: 4px; border-top-right-radius: 4px;
            }
            QTabBar::tab:selected { background: #45475a; color: #89b4fa; }
            QStatusBar { background: #181825; color: #a6adc8; }
        """)

    # ── Actions ─────────────────────────────────────────────────────────────────

    def _start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target.")
            return

        scan_type = self.scan_type_combo.currentText()
        url = f"{self.config['api_url']}/scan/{scan_type}"

        self.scan_btn.setEnabled(False)
        self._log(f"Starting {scan_type} scan: {target}")
        self.status_bar.showMessage(f"Scanning {target}...")

        worker = APIWorker("POST", url, {"target": target})
        worker.finished.connect(self._on_scan_queued)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(self._on_api_error)
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _run_ai(self):
        file_path = QFileDialog.getOpenFileName(
            self, "Select Scan Result", "/workspace/output", "JSON Files (*.json)"
        )[0]
        if not file_path:
            return

        url = f"{self.config['api_url']}/ai/analyze"
        self.ai_btn.setEnabled(False)
        self._log(f"Starting AI analysis: {os.path.basename(file_path)}")
        self.status_bar.showMessage("Running AI analysis...")

        worker = APIWorker("POST", url, {"file_path": file_path})
        worker.finished.connect(self._on_scan_queued)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(self._on_api_error)
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _on_scan_queued(self, data: dict):
        task_id = data.get("task_id")
        self.current_task_id = task_id
        self._log(f"Task queued: {task_id}")
        self.status_bar.showMessage(f"Task {task_id} running...")
        self.poll_timer.start(self.config["poll_interval_ms"])

    def _on_api_error(self, err: str):
        self.scan_btn.setEnabled(True)
        self.ai_btn.setEnabled(True)
        self._log(f"API Error: {err}")
        self.status_bar.showMessage("Error")

    def _poll_task(self):
        if not self.current_task_id:
            self.poll_timer.stop()
            return

        url = f"{self.config['api_url']}/task/{self.current_task_id}"
        worker = APIWorker("GET", url)
        worker.finished.connect(self._on_task_result)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(lambda e: self._log(f"Poll error: {e}"))
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _on_task_result(self, data: dict):
        status = data.get("status", "")
        if status == "SUCCESS":
            self.poll_timer.stop()
            self.scan_btn.setEnabled(True)
            self.ai_btn.setEnabled(True)
            self._log(f"Task completed: {self.current_task_id}")
            self.status_bar.showMessage("Done")
            self._load_results()
            self.current_task_id = None
        elif status == "FAILURE":
            self.poll_timer.stop()
            self.scan_btn.setEnabled(True)
            self.ai_btn.setEnabled(True)
            self._log(f"Task failed: {data.get('result', 'unknown')}")
            self.status_bar.showMessage("Task failed")
            self.current_task_id = None

    def _load_results(self):
        url = f"{self.config['api_url']}/results"
        worker = APIWorker("GET", url)
        worker.finished.connect(self._on_results)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(lambda e: self._log(f"Results error: {e}"))
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _on_results(self, data: dict):
        results = data.get("results", [])
        if isinstance(results, dict):
            results = results.get("results", [])
        if not results:
            self._log("No results found")
            return

        latest = results[-1].get("data", {})
        self._populate_vuln_table(latest)
        self._populate_attack_paths(latest)
        self._populate_summary(latest)

    def _populate_vuln_table(self, data: dict):
        vulns = data.get("vulnerabilities", data.get("analysis", {}).get("vulnerabilities", []))
        self.vuln_table.setRowCount(len(vulns))
        for i, v in enumerate(vulns):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(str(v.get("vuln_id", ""))))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(str(v.get("name", ""))))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(str(v.get("type", v.get("classification", "")))))
            severity = str(v.get("severity", ""))
            score = v.get("risk_score", "")

            sev_item = QTableWidgetItem(severity)
            sev_colors = {"critical": "#f38ba8", "high": "#fab387", "medium": "#f9e2af", "low": "#a6e3a1"}
            sev_item.setForeground(QColor(sev_colors.get(severity.lower(), "#cdd6f4")))
            self.vuln_table.setItem(i, 3, sev_item)

            score_item = QTableWidgetItem(str(score))
            if isinstance(score, (int, float)):
                if score >= 9:
                    score_item.setForeground(QColor("#f38ba8"))
                elif score >= 7:
                    score_item.setForeground(QColor("#fab387"))
                elif score >= 4:
                    score_item.setForeground(QColor("#f9e2af"))
                else:
                    score_item.setForeground(QColor("#a6e3a1"))
            self.vuln_table.setItem(i, 4, score_item)

    def _populate_attack_paths(self, data: dict):
        paths = data.get("attack_paths", data.get("analysis", {}).get("attack_paths", []))
        if not paths:
            self.path_text.setPlainText("No attack paths available.")
            return

        lines = []
        for p in paths:
            lines.append(f"[{p.get('priority', '').upper()}] {p.get('name', '')}")
            for step in p.get("steps", []):
                lines.append(f"  Step {step.get('step')}: {step.get('action')} — {step.get('description')}")
                if step.get("target"):
                    lines.append(f"    Target: {step.get('target')}")
            lines.append("")
        self.path_text.setPlainText("\n".join(lines))

    def _populate_summary(self, data: dict):
        summary = data.get("summary", data.get("analysis", {}).get("summary", {}))
        if not summary:
            self.summary_text.setPlainText("No summary available.")
            return

        lines = [
            "=== Scan Summary ===",
            f"Total vulnerabilities: {summary.get('total', 0)}",
            f"  Critical: {summary.get('critical', 0)}",
            f"  High:     {summary.get('high', 0)}",
            f"  Medium:   {summary.get('medium', 0)}",
            f"  Low:      {summary.get('low', 0)}",
        ]
        self.summary_text.setPlainText("\n".join(lines))

    # ── Export ──────────────────────────────────────────────────────────────────

    def _export_report(self, fmt: str):
        if fmt == "json":
            path, _ = QFileDialog.getSaveFileName(self, "Save JSON Report", "report.json", "JSON (*.json)")
        else:
            path, _ = QFileDialog.getSaveFileName(self, "Save HTML Report", "report.html", "HTML (*.html)")

        if not path:
            return

        report_data = self._collect_report_data()

        if fmt == "json":
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
        else:
            html_content = self._render_html_report(report_data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)

        self._log(f"Report exported: {path}")
        self.status_bar.showMessage(f"Exported: {path}")

    def _collect_report_data(self) -> dict:
        vulns = []
        for row in range(self.vuln_table.rowCount()):
            vulns.append({
                "vuln_id": self.vuln_table.item(row, 0).text() if self.vuln_table.item(row, 0) else "",
                "name": self.vuln_table.item(row, 1).text() if self.vuln_table.item(row, 1) else "",
                "type": self.vuln_table.item(row, 2).text() if self.vuln_table.item(row, 2) else "",
                "severity": self.vuln_table.item(row, 3).text() if self.vuln_table.item(row, 3) else "",
                "risk_score": self.vuln_table.item(row, 4).text() if self.vuln_table.item(row, 4) else "",
            })

        return {
            "generated_at": datetime.now().isoformat(),
            "target": self.target_input.text().strip(),
            "vulnerabilities": vulns,
            "attack_paths": self.path_text.toPlainText(),
            "summary": self.summary_text.toPlainText(),
            "log": self.log_window.toPlainText(),
        }

    def _render_html_report(self, data: dict) -> str:
        vuln_rows = ""
        for v in data["vulnerabilities"]:
            sev = v["severity"].lower()
            color = {"critical": "#f38ba8", "high": "#fab387", "medium": "#f9e2af", "low": "#a6e3a1"}.get(sev, "#cdd6f4")
            vuln_rows += f"""
            <tr>
                <td>{html.escape(v['vuln_id'])}</td>
                <td>{html.escape(v['name'])}</td>
                <td>{html.escape(v['type'])}</td>
                <td style="color:{color};font-weight:bold">{html.escape(v['severity'])}</td>
                <td>{html.escape(v['risk_score'])}</td>
            </tr>"""

        esc = html.escape
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AutoSec Report</title>
<style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #1e1e2e; color: #cdd6f4; padding: 30px; }}
    h1 {{ color: #89b4fa; }} h2 {{ color: #f9e2af; margin-top: 28px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
    th, td {{ border: 1px solid #45475a; padding: 8px 12px; text-align: left; }}
    th {{ background: #313244; color: #89b4fa; }}
    pre {{ background: #181825; color: #a6e3a1; padding: 16px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
    .meta {{ color: #a6adc8; font-size: 0.9em; }}
</style></head><body>
<h1>AutoSec Platform Report</h1>
<p class="meta">Generated: {esc(data['generated_at'])} &nbsp;|&nbsp; Target: <strong>{esc(data['target'])}</strong></p>

<h2>Vulnerabilities</h2>
<table><tr><th>ID</th><th>Name</th><th>Type</th><th>Severity</th><th>Risk Score</th></tr>
{vuln_rows}</table>

<h2>Attack Paths</h2><pre>{esc(data['attack_paths'])}</pre>

<h2>Summary</h2><pre>{esc(data['summary'])}</pre>

<h2>Log</h2><pre>{esc(data['log'])}</pre>
</body></html>"""

    # ── Settings ────────────────────────────────────────────────────────────────

    def _open_settings(self):
        dlg = ConfigDialog(self.config, self)
        if dlg.exec_() == QDialog.Accepted:
            self.config = dlg.config
            save_config(self.config)
            self._log(f"Config saved. API: {self.config['api_url']}")

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _cleanup_worker(self, worker: APIWorker):
        if worker in self._workers:
            self._workers.remove(worker)

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_window.append(f"[{ts}] {msg}")


# ── Entry Point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AutoSecGUI()
    window.show()
    sys.exit(app.exec_())
