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
    QFormLayout, QDialogButtonBox, QSpinBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor

import requests


# ── Config ──────────────────────────────────────────────────────────────────────

if getattr(sys, 'frozen', False):
    CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".autosec_config.json")
else:
    CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

DEFAULT_CONFIG = {
    "api_url": "http://localhost:8000",
    "poll_interval_ms": 2000,
    "result_limit": 50,
}


def load_config() -> dict:
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()


def save_config(config: dict):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)


# ── Async API Worker ────────────────────────────────────────────────────────────

class APIWorker(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, method: str, url: str, data: dict = None, timeout: int = 10):
        super().__init__()
        self.method = method
        self.url = url
        self.data = data
        self.timeout = timeout

    def run(self):
        try:
            if self.method == "POST":
                resp = requests.post(self.url, json=self.data, timeout=self.timeout)
            else:
                resp = requests.get(self.url, timeout=self.timeout)
            resp.raise_for_status()
            self.finished.emit(resp.json())
        except Exception as e:
            self.error.emit(str(e))


class SSEWorker(QThread):
    """Reads Server-Sent Events from a POST endpoint and emits per-event signals."""
    event = pyqtSignal(dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, url: str, data: dict, timeout: int = 300):
        super().__init__()
        self.url = url
        self.data = data
        self.timeout = timeout
        self._stop_requested = False

    def request_stop(self):
        self._stop_requested = True

    def run(self):
        try:
            with requests.post(self.url, json=self.data, timeout=self.timeout, stream=True) as resp:
                resp.raise_for_status()
                for line in resp.iter_lines(decode_unicode=True):
                    if self._stop_requested:
                        break
                    if not line or not line.startswith("data: "):
                        continue
                    payload = line[6:]
                    if payload.strip() == "[DONE]":
                        break
                    try:
                        self.event.emit(json.loads(payload))
                    except json.JSONDecodeError:
                        pass
            self.finished.emit()
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
        self.results_cache: list[dict] = []
        self.current_result: dict = {}
        self.current_result_file = None
        self._loading_results = False
        self.poll_timer = QTimer(self)
        self.poll_timer.timeout.connect(self._poll_task)
        self._workers: list[APIWorker] = []

        self.setWindowTitle("AutoSec Platform")
        self.setGeometry(100, 100, 1200, 750)
        self._build_menu()
        self._build_ui()
        self._apply_style()
        QTimer.singleShot(0, self._load_results)

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
        self.scan_type_combo.addItems(["web", "cve", "intranet", "ad", "recon", "persistence"])
        input_layout.addWidget(self.scan_type_combo)

        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self._start_scan)
        input_layout.addWidget(self.scan_btn)

        self.ai_btn = QPushButton("Run AI Analysis")
        self.ai_btn.clicked.connect(self._run_ai)
        input_layout.addWidget(self.ai_btn)

        self.auto_btn = QPushButton("One-Click Pentest")
        self.auto_btn.setStyleSheet("background: #f38ba8; color: #1e1e2e;")
        self.auto_btn.clicked.connect(self._auto_pentest)
        input_layout.addWidget(self.auto_btn)

        main_layout.addWidget(input_group)

        # ── Result History ──
        history_group = QGroupBox("Result History")
        history_layout = QHBoxLayout(history_group)

        history_layout.addWidget(QLabel("Result:"))
        self.result_combo = QComboBox()
        self.result_combo.currentIndexChanged.connect(self._on_result_selected)
        history_layout.addWidget(self.result_combo, 1)

        self.refresh_btn = QPushButton("Refresh Results")
        self.refresh_btn.clicked.connect(self._load_results)
        history_layout.addWidget(self.refresh_btn)

        main_layout.addWidget(history_group)

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

        # AI Suggestions (for auto pentest results)
        self.suggest_text = QTextEdit()
        self.suggest_text.setReadOnly(True)
        self.suggest_text.setFont(QFont("Consolas", 10))
        tabs.addTab(self.suggest_text, "AI Suggestions")

        # CTF Solver tab
        ctf_tab = QWidget()
        ctf_layout = QVBoxLayout(ctf_tab)

        ctf_input_group = QGroupBox("Challenge Info")
        ctf_input_layout = QVBoxLayout(ctf_input_group)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("URL:"))
        self.ctf_url_input = QLineEdit()
        self.ctf_url_input.setPlaceholderText("Challenge URL or target (e.g. http://ctf.example.com:8080)")
        row1.addWidget(self.ctf_url_input, 1)
        ctf_input_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Description:"))
        self.ctf_desc_input = QTextEdit()
        self.ctf_desc_input.setPlaceholderText("Challenge description, hints, or file info...")
        self.ctf_desc_input.setMaximumHeight(80)
        row2.addWidget(self.ctf_desc_input, 1)
        ctf_input_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Category:"))
        self.ctf_category_combo = QComboBox()
        self.ctf_category_combo.addItems(["web", "pwn", "crypto", "misc", "reverse", "forensics", "osint", "malware"])
        row3.addWidget(self.ctf_category_combo)
        row3.addWidget(QLabel("CTF Name:"))
        self.ctf_name_input = QLineEdit()
        self.ctf_name_input.setPlaceholderText("Optional")
        row3.addWidget(self.ctf_name_input)
        row3.addWidget(QLabel("Timeout:"))
        self.ctf_timeout_spin = QSpinBox()
        self.ctf_timeout_spin.setRange(60, 1800)
        self.ctf_timeout_spin.setValue(300)
        self.ctf_timeout_spin.setSuffix("s")
        row3.addWidget(self.ctf_timeout_spin)
        self.ctf_solve_btn = QPushButton("Solve")
        self.ctf_solve_btn.setStyleSheet("background: #a6e3a1; color: #1e1e2e;")
        self.ctf_solve_btn.clicked.connect(self._ctf_solve)
        row3.addWidget(self.ctf_solve_btn)

        self.ctf_stop_btn = QPushButton("Stop")
        self.ctf_stop_btn.setStyleSheet("background: #f38ba8; color: #1e1e2e;")
        self.ctf_stop_btn.clicked.connect(self._ctf_stop)
        self.ctf_stop_btn.setEnabled(False)
        row3.addWidget(self.ctf_stop_btn)

        ctf_input_layout.addLayout(row3)

        ctf_layout.addWidget(ctf_input_group)

        # Flag display (hidden by default)
        self.ctf_flag_label = QLabel("")
        self.ctf_flag_label.setFont(QFont("Consolas", 16, QFont.Bold))
        self.ctf_flag_label.setStyleSheet("color: #a6e3a1; padding: 10px;")
        self.ctf_flag_label.setAlignment(Qt.AlignCenter)
        self.ctf_flag_label.hide()
        ctf_layout.addWidget(self.ctf_flag_label)

        # Agent reasoning display
        self.ctf_output = QTextEdit()
        self.ctf_output.setReadOnly(True)
        self.ctf_output.setFont(QFont("Consolas", 10))
        ctf_layout.addWidget(self.ctf_output, 1)

        tabs.addTab(ctf_tab, "CTF Solver")

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
        entry = self.result_combo.currentData() if self.result_combo.count() else None
        filename = entry.get("file") if isinstance(entry, dict) else None
        data = entry.get("data", {}) if isinstance(entry, dict) else {}

        if not filename:
            QMessageBox.warning(self, "Warning", "Please load or select a scan result first.")
            return

        if data.get("scan_type") == "ai_analysis":
            QMessageBox.warning(self, "Warning", "Please select a raw scan result, not an AI analysis result.")
            return

        url = f"{self.config['api_url']}/ai/analyze"
        self.ai_btn.setEnabled(False)
        self._log(f"Starting AI analysis: {filename}")
        self.status_bar.showMessage("Running AI analysis...")

        worker = APIWorker("POST", url, {"filename": filename})
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

    def _auto_pentest(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target.")
            return

        url = f"{self.config['api_url']}/pentest/auto"
        self.auto_btn.setEnabled(False)
        self.scan_btn.setEnabled(False)
        self.ai_btn.setEnabled(False)
        self._log(f"[Auto Pentest] Starting full pipeline: {target}")
        self.status_bar.showMessage("Running auto pentest pipeline...")

        worker = APIWorker("POST", url, {"target": target}, timeout=600)
        worker.finished.connect(self._on_auto_pentest_result)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(self._on_api_error)
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _on_auto_pentest_result(self, data: dict):
        self.auto_btn.setEnabled(True)
        self.scan_btn.setEnabled(True)
        self.ai_btn.setEnabled(True)

        status = data.get("status", "")
        errors = data.get("errors", [])
        target = data.get("target", "")

        self._log(f"[Auto Pentest] Pipeline completed: {status}")
        for stage in data.get("stages", []):
            self._log(f"[Auto Pentest]   - {stage}: done")
        for err in errors:
            self._log(f"[Auto Pentest]   WARNING: {err}")

        # Populate vuln table from ai_analysis
        ai = data.get("ai_analysis", {})
        self._populate_vuln_table(ai if "vulnerabilities" in ai else data)

        # Populate attack paths from ai_analysis
        self._populate_attack_paths(ai if "attack_paths" in ai else data)

        # Populate AI Suggestions tab
        self._populate_ai_suggestions(data)

        # Populate summary
        scan = data.get("scan_results", {})
        summary_data = {
            "target": target,
            "scan_type": "auto_pentest",
            "status": status,
            "result": scan,
            **ai,
        }
        self._populate_summary(summary_data)

        self.status_bar.showMessage("Auto pentest completed")

    # ── CTF Solver ──────────────────────────────────────────────────────────────

    def _ctf_solve(self):
        url = self.ctf_url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a challenge URL.")
            return

        description = self.ctf_desc_input.toPlainText().strip()
        if not description:
            QMessageBox.warning(self, "Warning", "Please enter a challenge description.")
            return

        self.ctf_solve_btn.setEnabled(False)
        self.ctf_stop_btn.setEnabled(True)
        self.ctf_flag_label.hide()
        self.ctf_output.clear()
        self._log(f"[CTF] Starting solver: {url}")
        self.status_bar.showMessage("CTF solver running...")

        api_url = f"{self.config['api_url']}/ctf/solve"
        data = {
            "url": url,
            "description": description,
            "category": self.ctf_category_combo.currentText(),
            "ctf_name": self.ctf_name_input.text().strip(),
            "timeout": self.ctf_timeout_spin.value(),
        }

        self._ctf_worker = SSEWorker(api_url, data, timeout=self.ctf_timeout_spin.value())
        self._ctf_worker.event.connect(self._on_ctf_event)
        self._ctf_worker.finished.connect(self._on_ctf_finished)
        self._ctf_worker.error.connect(self._on_ctf_error)
        self._ctf_worker.start()

    def _ctf_stop(self):
        if hasattr(self, "_ctf_worker") and self._ctf_worker.isRunning():
            self._ctf_worker.request_stop()
            self._log("[CTF] Stop requested")
            self.status_bar.showMessage("CTF solver stopping...")

    def _on_ctf_event(self, data: dict):
        status = data.get("status", "")
        round_num = data.get("round", 0)
        thought = data.get("thought", "")
        action = data.get("action", "")
        observation = data.get("observation", "")
        flag = data.get("flag")

        cursor = self.ctf_output.textCursor()
        cursor.movePosition(cursor.End)

        def _html(text, color=None):
            if color:
                return f'<span style="color:{color};font-size:12px">{text}</span><br>'
            return f'<span style="font-size:12px">{text}</span><br>'

        cursor.insertHtml(_html(f'<br>{"═" * 40}', "#89b4fa"))
        cursor.insertHtml(_html(f'═══ Round {round_num} {"═" * (35 - len(str(round_num)))}', "#89b4fa"))

        if thought:
            cursor.insertHtml(_html(f'<br>💭 <b>Thought:</b>', "#89d4ef"))
            for line in thought.split("\n"):
                cursor.insertHtml(_html(f'  {line}', "#89d4ef"))

        if action:
            cursor.insertHtml(_html(f'<br>⚡ <b>Action:</b>', "#f9e2af"))
            for line in action.split("\n"):
                cursor.insertHtml(_html(f'  {line}', "#f9e2af"))

        if observation:
            cursor.insertHtml(_html(f'<br>📋 <b>Observation:</b>', "#cdd6f4"))
            for line in observation.split("\n"):
                cursor.insertHtml(_html(f'  {line}', "#a6adc8"))

        if flag:
            cursor.insertHtml(_html(f'<br>{"🎉" * 5}', "#a6e3a1"))
            cursor.insertHtml(
                f'<span style="color:#a6e3a1;font-size:18px;font:bold">'
                f'FLAG: {flag}</span><br>')
            cursor.insertHtml(_html(f'{"🎉" * 5}', "#a6e3a1"))
            self.ctf_flag_label.setText(f"FLAG: {flag}")
            self.ctf_flag_label.show()
            self._log(f"[CTF] FLAG FOUND: {flag}")

        if status == "max_rounds_reached":
            msg = data.get("message", "Reached maximum rounds without finding flag.")
            cursor.insertHtml(_html(f'<br>{msg}', "#f38ba8"))

        self.ctf_output.setTextCursor(cursor)
        self.ctf_output.ensureCursorVisible()

    def _on_ctf_finished(self):
        self.ctf_solve_btn.setEnabled(True)
        self.ctf_stop_btn.setEnabled(False)
        self.status_bar.showMessage("CTF solver finished")
        self._log("[CTF] Solver finished")

    def _on_ctf_error(self, err: str):
        self.ctf_solve_btn.setEnabled(True)
        self.ctf_stop_btn.setEnabled(False)
        self._log(f"[CTF] Error: {err}")
        self.status_bar.showMessage("CTF solver error")
        cursor = self.ctf_output.textCursor()
        cursor.movePosition(cursor.End)
        cursor.insertHtml(
            f'<span style="color:#f38ba8;font-size:12px"><br>Error: {err}</span><br>')
        self.ctf_output.setTextCursor(cursor)

    @staticmethod
    def _unwrap_raw(d: dict) -> dict:
        """If d only has raw_response, try to parse JSON from it."""
        if "raw_response" in d and len(d) == 1:
            raw = d["raw_response"]
            # Strip markdown code fences
            import re
            cleaned = re.sub(r"^```(?:json)?\s*\n?", "", raw.strip())
            cleaned = re.sub(r"\n?```\s*$", "", cleaned)
            try:
                return json.loads(cleaned)
            except (json.JSONDecodeError, Exception):
                pass
        return d

    def _populate_ai_suggestions(self, data: dict):
        self.suggest_text.clear()
        cursor = self.suggest_text.textCursor()
        cursor.insertHtml('<span style="font-size:13px"> </span>')

        sev_colors = {"严重": "#f38ba8", "critical": "#f38ba8", "高": "#fab387", "high": "#fab387",
                       "中": "#f9e2af", "medium": "#f9e2af", "低": "#a6e3a1", "low": "#a6e3a1",
                       "info": "#89b4fa"}
        sev_zh_map = {"critical": "严重", "high": "高", "medium": "中", "low": "低", "info": "信息",
                       "严重": "严重", "高": "高", "中": "中", "低": "低"}
        sev_icon = {"严重": "🔴", "critical": "🔴", "高": "🟠", "high": "🟠",
                     "中": "🟡", "medium": "🟡", "低": "🟢", "low": "🟢", "info": "🔵"}

        def _heading(text):
            cursor.insertHtml(
                f'<br><span style="color:#89b4fa;font-size:15px;font:bold">━━ {text} ━━</span><br><br>')

        def _line(text, color=None):
            if color:
                cursor.insertHtml(f'<span style="color:{color};font-size:12px">{text}</span><br>')
            else:
                cursor.insertHtml(f'<span style="font-size:12px">{text}</span><br>')

        def _kv(key, value, val_color=None):
            if val_color:
                cursor.insertHtml(
                    f'<span style="color:#cdd6f4;font:bold;font-size:12px">{key}：</span>'
                    f'<span style="color:{val_color};font-size:12px">{value}</span><br>')
            else:
                cursor.insertHtml(
                    f'<span style="color:#cdd6f4;font:bold;font-size:12px">{key}：</span>'
                    f'<span style="font-size:12px">{value}</span><br>')

        def _card_sep():
            cursor.insertHtml(
                '<span style="color:#45475a;font-size:11px">'
                '────────────────────────────────────────</span><br>')

        has_content = False

        # ── PentestGPT ──
        pentest = self._unwrap_raw(data.get("pentest_suggestions", {}))
        if pentest and not pentest.get("error"):
            has_content = True
            _heading("PentestGPT 漏洞分析")

            summary = pentest.get("summary", "")
            if summary:
                _line(f'{summary}')
                _line("")

            findings = pentest.get("findings", [])
            if findings:
                for i, f in enumerate(findings, 1):
                    if isinstance(f, dict):
                        name = f.get("name", f"发现 {i}")
                        sev = f.get("severity", "info")
                        sev_zh = sev_zh_map.get(sev, sev)
                        color = sev_colors.get(sev, "#cdd6f4")
                        icon = sev_icon.get(sev, "🔵")
                        cursor.insertHtml(
                            f'<span style="color:{color};font:bold;font-size:13px">'
                            f'{icon} [{sev_zh}] {name}</span><br>')
                        desc = f.get("description", "")
                        if desc:
                            _kv("描述", desc)
                        evidence = f.get("evidence", "")
                        if evidence:
                            _kv("证据", str(evidence))
                        risk = f.get("risk", "")
                        if risk:
                            _kv("风险", risk, color)
                        remediation = f.get("remediation", "")
                        if remediation:
                            _kv("修复建议", remediation, "#a6e3a1")
                        _card_sep()
                    else:
                        _line(f"  {i}. {f}")

            next_steps = pentest.get("next_steps", [])
            if next_steps:
                _heading("建议下一步操作")
                for i, s in enumerate(next_steps, 1):
                    if isinstance(s, dict):
                        _line(f"  {i}. {s.get('description', s)}")
                    else:
                        _line(f"  {i}. {s}")

            notes = pentest.get("notes", "")
            if notes:
                _line("")
                _kv("备注", notes, "#a6adc8")

        # ── Shannon ──
        chain = self._unwrap_raw(data.get("attack_chain", {}))
        if chain and not chain.get("error"):
            has_content = True
            _heading("Shannon 攻击链规划")
            chain_id = chain.get("chain_id", "")
            if chain_id:
                _kv("攻击链编号", chain_id, "#89b4fa")
            steps = chain.get("steps", [])
            if steps:
                _line("")
                for i, s in enumerate(steps, 1):
                    action = s.get("action", "")
                    tool = s.get("tool", "")
                    desc = s.get("description", "")
                    risk = s.get("risk_level", "中")
                    color = sev_colors.get(risk, "#cdd6f4")
                    risk_zh = sev_zh_map.get(risk, risk)
                    icon = sev_icon.get(risk, "🟡")
                    cursor.insertHtml(
                        f'<span style="color:{color};font:bold;font-size:13px">第{i}步</span>'
                        f'<span style="color:#cdd6f4;font-size:13px">  {action}</span>'
                        f'<span style="color:#89b4fa;font-size:13px">  [{tool}]</span><br>')
                    if desc:
                        cursor.insertHtml(
                            f'<span style="color:#a6adc8;font-size:12px">    {desc}</span><br>')
                    cursor.insertHtml(
                        f'<span style="color:{color};font-size:12px">    '
                        f'{icon} 风险等级：{risk_zh}</span><br><br>')

        if not has_content:
            _line("暂无 AI 建议。")

        # Populate summary
        scan = data.get("scan_results", {})
        summary_data = {
            "target": target,
            "scan_type": "auto_pentest",
            "status": status,
            "result": scan,
            **ai,
        }
        self._populate_summary(summary_data)

        self.status_bar.showMessage("Auto pentest completed")

    def _on_api_error(self, err: str):
        self.scan_btn.setEnabled(True)
        self.ai_btn.setEnabled(True)
        self.auto_btn.setEnabled(True)
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
            task_result = data.get("result") or {}
            self.poll_timer.stop()
            self.scan_btn.setEnabled(True)
            self.ai_btn.setEnabled(True)
            self.auto_btn.setEnabled(True)
            if task_result.get("status") == "failed":
                self._log(f"Task finished with errors: {task_result.get('errors', [])}")
                self.status_bar.showMessage("Task finished with errors")
            else:
                self._log(f"Task completed: {self.current_task_id}")
                self.status_bar.showMessage("Done")
            self._load_results()
            self.current_task_id = None
        elif status == "FAILURE":
            self.poll_timer.stop()
            self.scan_btn.setEnabled(True)
            self.ai_btn.setEnabled(True)
            self.auto_btn.setEnabled(True)
            self._log(f"Task failed: {data.get('result', 'unknown')}")
            self.status_bar.showMessage("Task failed")
            self.current_task_id = None

    def _load_results(self):
        url = f"{self.config['api_url']}/results?limit={self.config.get('result_limit', 50)}"
        self.refresh_btn.setEnabled(False) if hasattr(self, "refresh_btn") else None
        worker = APIWorker("GET", url)
        worker.finished.connect(self._on_results)
        worker.finished.connect(lambda: self._cleanup_worker(worker))
        worker.error.connect(lambda e: self._log(f"Results error: {e}"))
        worker.error.connect(lambda _: self.refresh_btn.setEnabled(True) if hasattr(self, "refresh_btn") else None)
        worker.error.connect(lambda _: self._cleanup_worker(worker))
        self._workers.append(worker)
        worker.start()

    def _on_results(self, data: dict):
        if hasattr(self, "refresh_btn"):
            self.refresh_btn.setEnabled(True)

        results = data.get("results", [])
        if isinstance(results, dict):
            results = results.get("results", [])
        self.results_cache = results

        if hasattr(self, "result_combo"):
            self._loading_results = True
            self.result_combo.clear()
            for entry in results:
                label = self._result_label(entry)
                self.result_combo.addItem(label, entry)
            self._loading_results = False

        if not results:
            self._log("No results found")
            return

        if self.result_combo.count():
            self.result_combo.setCurrentIndex(0)
        self._display_result_entry(results[0])

    def _result_label(self, entry: dict) -> str:
        file_name = entry.get("file", "")
        scan_type = entry.get("scan_type", "unknown")
        target = entry.get("target", "")
        status = entry.get("status", "")
        return f"{file_name} | {scan_type} | {status} | {target}"

    def _on_result_selected(self, index: int):
        if self._loading_results or index < 0:
            return
        entry = self.result_combo.itemData(index)
        if isinstance(entry, dict):
            self._display_result_entry(entry)

    def _display_result_entry(self, entry: dict):
        data = entry.get("data", {}) if isinstance(entry, dict) else {}
        self.current_result = data
        self.current_result_file = entry.get("file") if isinstance(entry, dict) else None
        if data.get("target") and not self.target_input.text().strip():
            self.target_input.setText(str(data.get("target")))
        self._populate_vuln_table(data)
        self._populate_attack_paths(data)
        self._populate_summary(data)

    def _populate_vuln_table(self, data: dict):
        analysis = self._analysis_payload(data)
        vulns = analysis.get("vulnerabilities", data.get("vulnerabilities", []))

        # Deduplicate by (name, type)
        seen = set()
        unique_vulns = []
        for v in vulns:
            key = (v.get("name", ""), v.get("type", ""))
            if key not in seen:
                seen.add(key)
                unique_vulns.append(v)
        vulns = unique_vulns

        sev_colors = {"critical": "#f38ba8", "high": "#fab387", "medium": "#f9e2af", "low": "#a6e3a1",
                       "严重": "#f38ba8", "高": "#fab387", "中": "#f9e2af", "低": "#a6e3a1"}
        sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢",
                     "严重": "🔴", "高": "🟠", "中": "🟡", "低": "🟢"}
        sev_zh = {"critical": "严重", "high": "高", "medium": "中", "low": "低",
                   "严重": "严重", "高": "高", "中": "中", "低": "低"}

        self.vuln_table.setRowCount(len(vulns))
        for i, v in enumerate(vulns):
            self.vuln_table.setItem(i, 0, QTableWidgetItem(str(v.get("vuln_id", ""))))
            self.vuln_table.setItem(i, 1, QTableWidgetItem(str(v.get("name", ""))))
            self.vuln_table.setItem(i, 2, QTableWidgetItem(str(v.get("type", v.get("classification", "")))))

            severity = str(v.get("severity", "info")).lower()
            score = v.get("risk_score", "")

            icon = sev_icon.get(severity, "🔵")
            label = sev_zh.get(severity, severity)
            sev_item = QTableWidgetItem(f"{icon} {label}")
            sev_item.setForeground(QColor(sev_colors.get(severity, "#cdd6f4")))
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
        analysis = self._analysis_payload(data)
        paths = analysis.get("attack_paths", data.get("attack_paths", []))
        recommendations = analysis.get("recommendations", data.get("recommendations", []))
        notice = analysis.get("authorization_notice", data.get("authorization_notice", ""))
        if not paths and not recommendations:
            self.path_text.setPlainText("No AI analysis available for this result yet.")
            return

        lines = []
        if notice:
            lines.append(f"Authorization: {notice}")
            lines.append("")
        for p in paths:
            lines.append(f"[{p.get('priority', '').upper()}] {p.get('name', '')}")
            for step in p.get("steps", []):
                lines.append(f"  Step {step.get('step')}: {step.get('action')} — {step.get('description')}")
                if step.get("target"):
                    lines.append(f"    Target: {step.get('target')}")
            lines.append("")
        if recommendations:
            lines.append("Recommendations:")
            for item in recommendations:
                lines.append(f"- {item}")
        self.path_text.setPlainText("\n".join(lines))

    def _populate_summary(self, data: dict):
        analysis = self._analysis_payload(data)
        summary = analysis.get("summary", data.get("summary", {}))
        observations = analysis.get("observations", data.get("observations", []))
        errors = data.get("errors", []) + analysis.get("errors", [])
        warnings = data.get("warnings", []) + analysis.get("warnings", [])

        lines = [
            "=== Scan Summary ===",
            f"File: {self.current_result_file or ''}",
            f"Target: {data.get('target', '')}",
            f"Scan type: {data.get('scan_type', '')}",
            f"Status: {data.get('status', '')}",
            f"Total vulnerabilities: {summary.get('total', 0)}",
            f"  Critical: {summary.get('critical', 0)}",
            f"  High:     {summary.get('high', 0)}",
            f"  Medium:   {summary.get('medium', 0)}",
            f"  Low:      {summary.get('low', 0)}",
            f"Open service observations: {len(observations)}",
        ]
        if observations:
            lines.append("")
            lines.append("=== Observations ===")
            for obs in observations:
                lines.append(f"- {obs.get('port', '')}/{obs.get('protocol', '')} {obs.get('service', '')} {obs.get('description', '')}".strip())
        if warnings:
            lines.append("")
            lines.append("=== Warnings ===")
            for warning in warnings:
                lines.append(f"- {warning}")
        if errors:
            lines.append("")
            lines.append("=== Errors ===")
            for err in errors:
                lines.append(f"- {err}")
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
            "target": self.current_result.get("target", self.target_input.text().strip()),
            "result_file": self.current_result_file,
            "selected_result": self.current_result,
            "vulnerabilities": vulns,
            "attack_paths": self.path_text.toPlainText(),
            "ai_suggestions": self.suggest_text.toPlainText(),
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
<p class="meta">Generated: {esc(data['generated_at'])} &nbsp;|&nbsp; Target: <strong>{esc(data['target'])}</strong> &nbsp;|&nbsp; Result: {esc(str(data.get('result_file') or ''))}</p>

<h2>Vulnerabilities</h2>
<table><tr><th>ID</th><th>Name</th><th>Type</th><th>Severity</th><th>Risk Score</th></tr>
{vuln_rows}</table>

<h2>AI Analysis And Recommendations</h2><pre>{esc(data['attack_paths'])}</pre>

<h2>AI Suggestions</h2><pre>{esc(data.get('ai_suggestions', ''))}</pre>

<h2>Summary</h2><pre>{esc(data['summary'])}</pre>

<h2>Selected Result JSON</h2><pre>{esc(json.dumps(data.get('selected_result', {}), ensure_ascii=False, indent=2))}</pre>

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

    def _analysis_payload(self, data: dict) -> dict:
        if isinstance(data.get("analysis"), dict):
            return data["analysis"]
        if any(key in data for key in ("vulnerabilities", "observations", "attack_paths", "recommendations")):
            return data
        return {}

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_window.append(f"[{ts}] {msg}")


# ── Entry Point ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AutoSecGUI()
    window.show()
    sys.exit(app.exec_())
