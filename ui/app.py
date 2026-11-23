import sys
import os
import ctypes

# Проверка запуска в Windows-контексте (для вызовов WinAPI).
if os.name == "nt":
    ctypes.windll.shell32.IsUserAnAdmin()

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QAbstractItemView,
    QComboBox, QStackedWidget, QCheckBox, QLineEdit, QScrollArea,
    QFileDialog, QMenu, QProgressBar, QMessageBox, QCompleter, QInputDialog, QFrame
)
import ipaddress
from PyQt6.QtWebEngineWidgets import QWebEngineView
import json
import re
import time
import logging
import shutil
from PyQt6.QtCore import Qt, QTimer, QUrl, QSize, QSettings
from PyQt6.QtGui import QFont, QColor, QIcon, QPixmap, QPainter, QAction, QDesktopServices, QPen
import csv
from collections import defaultdict, deque
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from core.scanner import scan_network, scan_range, is_target_fully_local, get_local_subnet, get_network_interfaces, get_default_gateway, ContinuousMonitor
from core.version import __version__

# Общие QSS-стили для повторяющихся элементов интерфейса.
DARK_COMBO_QSS = """
    QComboBox {
        background-color: #2b2b2b;
        color: #aaaaaa;
        border: 1px solid #222222;
        padding: 4px 10px;
        font-size: 11px;
        border-radius: 8px;
    }
    QComboBox:hover { border-color: #ffffff; color: #ffffff; }
    QComboBox QAbstractItemView {
        background-color: #2b2b2b; color: #aaaaaa;
        selection-background-color: #ffffff; selection-color: #ffffff;
        border: 1px solid #3c3c3c;
    }
"""

APP_THEME_QSS = """
            QMainWindow, QWidget {
                background-color: #1f1f1f;
                color: #ffffff;
                font-family: 'Segoe UI', 'Inter', sans-serif;
                font-size: 13px;
            }
            QLabel {
                color: #ffffff;
            }
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #8a8a8a;
                border-radius: 8px;
                padding: 7px 16px;
                font-weight: 700;
                letter-spacing: 0.3px;
            }
            QPushButton:disabled {
                color: #bdbdbd;
                background-color: #2a2a2a;
                border-color: #3f3f3f;
            }
            QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 8px;
                padding: 6px 10px;
                selection-background-color: #5a5a5a;
                selection-color: #ffffff;
            }
            QLineEdit:focus, QComboBox:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #7a7a7a;
            }
            QComboBox::drop-down {
                border: none;
                width: 24px;
            }
            QTableWidget {
                background-color: #262626;
                alternate-background-color: #2d2d2d;
                gridline-color: #3a3a3a;
                border: 1px solid #3a3a3a;
                border-radius: 8px;
                color: #ffffff;
            }
            QTableWidget::item {
                padding: 4px;
            }
            QTableWidget::item:selected {
                background-color: #4a4a4a;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #303030;
                color: #e0e0e0;
                border: none;
                border-bottom: 1px solid #454545;
                border-right: 1px solid #6a6a6a;
                padding: 6px 10px;
                font-weight: 500;
            }
            QHeaderView::section:hover {
                background-color: #3a3a3a;
            }
            QScrollBar:vertical {
                background: #242424;
                width: 10px;
                margin: 2px;
            }
            QScrollBar::handle:vertical {
                background: #4a4a4a;
                border-radius: 4px;
                min-height: 24px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QLabel#subnet_label {
                color: #d6d6d6;
                font-size: 12px;
            }
            QLabel#title_label {
                color: #e0e0e0;
                font-size: 24px;
                font-weight: 500;
                letter-spacing: 1px;
            }
        """


from ui.widgets import LogoIniziale, SpinnerWidget, load_colored_svg

from ui.i18n import I18n
from ui.utils import is_valid_target
from ui.workers import (
    ActionWorker,
    AttackSurfaceWorker,
    CriticalHostsWorker,
    DiagnosticsWorker,
    GatewayCheckWorker,
    RangeScanWorker,
    ScanWorker,
    TrafficWorker,
)
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Eptal-Analyzer v{__version__}")
        self.setMinimumSize(1450, 780)

        icon_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
        self.setWindowIcon(QIcon(icon_path))

        self.live_timer = QTimer()
        self.live_timer.timeout.connect(self._live_scan)

        self.continuous_monitor = None
        self._monitor_active = False
        self.last_hosts = []
        self.previous_hosts = []
        self.event_log = []
        self._recent_targets = []
        self._target_profiles = []
        self._gateway_status = None
        self._gateway_check_running = False
        self._critical_hosts = []
        self._critical_status = {}
        self._critical_check_running = False
        self._task_queue = deque()
        self._active_task_name = None

        self.settings = QSettings("Eptal-Analyzer", "Eptal-Analyzer")
        self.i18n = I18n(self.settings.value("language", "ru", type=str))

        self._apply_theme()
        self._build_ui()
        self._load_settings()
        self.apply_language()
        QTimer.singleShot(500, self._check_dependencies)
        self.gateway_check_timer = QTimer(self)
        self.gateway_check_timer.setInterval(60000)
        self.gateway_check_timer.timeout.connect(self._start_gateway_check)
        self.gateway_check_timer.start()
        QTimer.singleShot(3000, self._start_gateway_check)
        self.critical_check_timer = QTimer(self)
        self.critical_check_timer.setInterval(60000)
        self.critical_check_timer.timeout.connect(self._start_critical_check)
        self.critical_check_timer.start()
        QTimer.singleShot(5000, self._start_critical_check)

    def _load_settings(self):
        # Загрузка сохранённых настроек интерфейса.
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        target = self.settings.value("scan_target", "", type=str)
        if target and hasattr(self, "scan_target"):
            self.scan_target.setText(target)
        iface_name = self.settings.value("iface_name", "", type=str)
        if iface_name and hasattr(self, "iface_selector"):
            for i in range(self.iface_selector.count()):
                data = self.iface_selector.itemData(i)
                if isinstance(data, dict) and data.get("name") == iface_name:
                    self.iface_selector.setCurrentIndex(i)
                    break
        recent = self.settings.value("recent_targets", [], type=list)
        if isinstance(recent, list):
            self._recent_targets = [str(x) for x in recent if str(x).strip()][:20]
        if hasattr(self, "scan_target"):
            self.scan_target.setCompleter(QCompleter(self._recent_targets, self))
        profiles = self.settings.value("target_profiles", [], type=list)
        if isinstance(profiles, list):
            self._target_profiles = [p for p in profiles if isinstance(p, dict) and p.get("name") and p.get("target")]
        if hasattr(self, "target_profile_combo"):
            self._refresh_target_profiles()
        critical = self.settings.value("critical_hosts", [], type=list)
        if isinstance(critical, list):
            self._critical_hosts = [str(x).strip() for x in critical if str(x).strip()][:50]

    def closeEvent(self, event):
        # Сохранение настроек при закрытии приложения.
        try:
            self.settings.setValue("geometry", self.saveGeometry())
            if hasattr(self, "scan_target"):
                self.settings.setValue("scan_target", self.scan_target.text())
            if hasattr(self, "iface_selector"):
                data = self.iface_selector.currentData()
                if isinstance(data, dict):
                    self.settings.setValue("iface_name", data.get("name", ""))
        except Exception:
            logging.getLogger(__name__).exception("Failed to save settings")
        super().closeEvent(event)

    def _get_log_path(self):
        # Путь к файлу лога приложения.
        log_dir = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Eptal-Analyzer")
        return os.path.join(log_dir, "eptal-analyzer.log")

    def _open_log(self):
        # Открытие файла лога в системе.
        path = self._get_log_path()
        if os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))
        else:
            self.statusBar().showMessage(f"Лог не найден: {path}")

    def _collect_diagnostics(self):
        # Сбор состояния зависимостей и окружения.
        checks = []
        nmap_path = shutil.which("nmap")
        checks.append(("Nmap", "OK" if nmap_path else "НЕ НАЙДЕН", nmap_path or "Не найден в PATH"))
        npcap_paths = [
            r"C:\Windows\System32\Npcap\wpcap.dll",
            r"C:\Windows\System32\Npcap\Packet.dll",
        ]
        npcap_ok = any(os.path.exists(p) for p in npcap_paths)
        checks.append(("Npcap", "OK" if npcap_ok else "НЕ НАЙДЕН", "wpcap.dll/Packet.dll" if npcap_ok else "Установите Npcap"))
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            logging.getLogger(__name__).debug("Failed to check admin rights", exc_info=True)
            is_admin = False
        checks.append(("Права администратора", "OK" if is_admin else "НЕТ", "Запустите от имени администратора" if not is_admin else ""))
        checks.append(("Python", "OK", sys.version.split()[0]))
        checks.append(("Лог", "OK" if os.path.exists(self._get_log_path()) else "НЕТ", self._get_log_path()))
        return checks

    def _show_diagnostics(self):
        # Показ диагностики окружения пользователю.
        checks = self._collect_diagnostics()
        lines = []
        for name, status, detail in checks:
            lines.append(f"{name}: {status}" + (f" — {detail}" if detail else ""))
        text = "\n".join(lines)
        box = QMessageBox(self)
        box.setWindowTitle("Диагностика окружения")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText("Состояние зависимостей Eptal-Analyzer")
        box.setInformativeText(text)
        open_log_btn = box.addButton("Открыть лог", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Ok)
        box.exec()
        if box.clickedButton() == open_log_btn:
            self._open_log()

    def _enqueue_task(self, name, fn):
        # Простая очередь задач UI: предотвращает конфликтующие операции.
        if self._active_task_name:
            self._task_queue.append((name, fn))
            self.statusBar().showMessage(f"Задача в очереди: {name} (активна: {self._active_task_name})")
            return
        self._active_task_name = name
        self.statusBar().showMessage(f"Задача запущена: {name}")
        try:
            fn()
        except Exception:
            logging.getLogger(__name__).exception("Task failed: %s", name)
            self._finish_task(name)

    def _finish_task(self, name=None):
        # Завершение активной задачи и запуск следующей из очереди.
        if name is None or self._active_task_name == name:
            self._active_task_name = None
        if not self._active_task_name and self._task_queue:
            next_name, next_fn = self._task_queue.popleft()
            self._active_task_name = next_name
            self.statusBar().showMessage(f"Задача запущена: {next_name}")
            try:
                next_fn()
            except Exception:
                logging.getLogger(__name__).exception("Task failed: %s", next_name)
                self._finish_task(next_name)

    def _start_gateway_check(self):
        # Периодическая проверка доступности шлюза.
        if self._gateway_check_running:
            return
        gateway = get_default_gateway()
        if not gateway:
            return
        self._gateway_check_running = True
        self._gateway_worker = GatewayCheckWorker(gateway)
        self._gateway_worker.result.connect(self._on_gateway_check)
        self._gateway_worker.finished.connect(lambda: setattr(self, "_gateway_check_running", False))
        self._gateway_worker.start()

    def _on_gateway_check(self, gateway, ok, detail=""):
        # Обработка результата проверки шлюза.
        ts = time.strftime("%H:%M:%S")
        prev = self._gateway_status
        self._gateway_status = ok
        detail_txt = f" — {detail}" if detail else ""
        self._append_availability_record("gateway", gateway, ok, detail)
        if prev is None:
            if not ok:
                event = f"[{ts}] ШЛЮЗ НЕДОСТУПЕН: {gateway}{detail_txt}"
                self.event_log.append(event)
                self.event_log = self.event_log[-200:]
                logging.getLogger(__name__).warning(event)
                self.statusBar().showMessage(event)
            return
        if prev != ok:
            event = f"[{ts}] ШЛЮЗ {'ДОСТУПЕН' if ok else 'НЕДОСТУПЕН'}: {gateway}{detail_txt}"
            self.event_log.append(event)
            self.event_log = self.event_log[-200:]
            logging.getLogger(__name__).warning(event)
            self.statusBar().showMessage(event)

    def _start_critical_check(self):
        # Периодическая проверка критичных узлов.
        if self._critical_check_running or not self._critical_hosts:
            return
        self._critical_check_running = True
        self._critical_worker = CriticalHostsWorker(list(self._critical_hosts))
        self._critical_worker.result.connect(self._on_critical_check)
        self._critical_worker.finished.connect(lambda: setattr(self, "_critical_check_running", False))
        self._critical_worker.start()

    def _on_critical_check(self, results):
        # Обработка результатов проверки критичных узлов.
        ts = time.strftime("%H:%M:%S")
        for host, info in results.items():
            ok = info.get("ok") if isinstance(info, dict) else bool(info)
            detail = info.get("detail", "") if isinstance(info, dict) else ""
            prev = self._critical_status.get(host)
            self._critical_status[host] = ok
            detail_txt = f" — {detail}" if detail else ""
            self._append_availability_record("critical", host, ok, detail)
            if prev is None:
                if not ok:
                    event = f"[{ts}] КРИТ. УЗЕЛ НЕДОСТУПЕН: {host}{detail_txt}"
                    self.event_log.append(event)
                    logging.getLogger(__name__).warning(event)
            elif prev != ok:
                event = f"[{ts}] КРИТ. УЗЕЛ {'ДОСТУПЕН' if ok else 'НЕДОСТУПЕН'}: {host}{detail_txt}"
                self.event_log.append(event)
                logging.getLogger(__name__).warning(event)
        self.event_log = self.event_log[-200:]

    def _manage_critical_hosts(self):
        # Управление списком критичных узлов для мониторинга.
        current = "\n".join(self._critical_hosts)
        text, ok = QInputDialog.getMultiLineText(self, "Критичные узлы", "Один IP/хост на строку:", current)
        if not ok:
            return
        hosts = [line.strip() for line in text.splitlines() if line.strip()]
        self._critical_hosts = hosts[:50]
        self._critical_status = {h: self._critical_status.get(h) for h in self._critical_hosts}
        self.settings.setValue("critical_hosts", self._critical_hosts)
        self.statusBar().showMessage(f"Критичных узлов: {len(self._critical_hosts)}")
        self._start_critical_check()

    def _record_scan_events(self, hosts):
        # Фиксация изменений между сканированиями для мониторинга доступности.
        current_ips = {h.get("ip") for h in hosts if h.get("ip")}
        previous_ips = {h.get("ip") for h in self.previous_hosts if h.get("ip")}
        if not self.previous_hosts:
            self.previous_hosts = list(hosts)
            return []

        appeared = sorted(current_ips - previous_ips)
        disappeared = sorted(previous_ips - current_ips)
        events = []
        ts = time.strftime("%H:%M:%S")
        for ip in appeared:
            events.append(f"[{ts}] ПОЯВИЛСЯ: {ip}")
        for ip in disappeared:
            events.append(f"[{ts}] ПРОПАЛ: {ip} — устройство недоступно (возможна потеря связи/выключение/обрыв)")

        gateway = None
        for h in hosts:
            role = (h.get("role") or "").lower()
            if role == "gateway" or h.get("ip", "").endswith(".1"):
                gateway = h.get("ip")
                break
        if gateway and gateway in disappeared:
            events.insert(0, f"[{ts}] ВНИМАНИЕ: шлюз {gateway} недоступен — возможна проблема сети/связи")

        if events:
            self.event_log.extend(events)
            self.event_log = self.event_log[-200:]
            for e in events:
                logging.getLogger(__name__).info("Event: %s", e)
        self.previous_hosts = list(hosts)
        return events

    def _show_events(self):
        # Показ журнала событий мониторинга.
        text = "\n".join(self.event_log[-200:]) if self.event_log else "Событий пока нет."
        box = QMessageBox(self)
        box.setWindowTitle("События мониторинга")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText("Журнал изменений доступности")
        box.setInformativeText(text[-4000:])
        box.addButton(QMessageBox.StandardButton.Ok)
        box.exec()

    def _export_report(self):
        # Экспорт HTML-отчёта по последнему сканированию.
        import html as html_lib
        path, _ = QFileDialog.getSaveFileName(self, "Сохранить отчёт", "eptal-report.html", "HTML (*.html)")
        if not path:
            return
        hosts = getattr(self, "last_hosts", []) or []
        rows = []
        ports_total = 0
        risky = 0
        role_counts = {}
        risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC", 135: "RPC"}
        risk_rows = []
        for h in hosts:
            open_ports = h.get("open_ports", []) or []
            ports_total += len(open_ports)
            role = str(h.get("role", "unknown"))
            role_counts[role] = role_counts.get(role, 0) + 1
            found_risky = [f"{p} ({risky_ports[p]})" for p in open_ports if p in risky_ports]
            if found_risky:
                risky += 1
                risk_rows.append(f"<tr><td>{html_lib.escape(str(h.get('ip','')))}</td><td>{html_lib.escape(str(h.get('hostname','')))}</td><td>{html_lib.escape(', '.join(found_risky))}</td></tr>")
            rows.append("<tr>" + "".join(
                f"<td>{html_lib.escape(str(h.get(k, '')))}</td>"
                for k in ["ip", "mac", "hostname", "vendor", "role", "os_hint"]
            ) + f"<td>{html_lib.escape(' '.join(map(str, open_ports)))}</td></tr>")
        events = "".join(f"<li>{html_lib.escape(e)}</li>" for e in self.event_log[-100:]) or "<li>Нет событий</li>"
        gw_status = "неизвестно"
        if self._gateway_status is True: gw_status = "доступен"
        if self._gateway_status is False: gw_status = "недоступен"
        crit = "".join(f"<li>{html_lib.escape(h)}: {'доступен' if self._critical_status.get(h) else 'недоступен/не проверен'}</li>" for h in self._critical_hosts) or "<li>Не настроены</li>"
        roles_html = "".join(f"<li>{html_lib.escape(k)}: {v}</li>" for k, v in sorted(role_counts.items())) or "<li>Нет данных</li>"
        risks_html = "".join(risk_rows) or "<tr><td colspan='3'>Явных типичных рисковых портов не найдено</td></tr>"
        html_doc = f"""<!doctype html><html><head><meta charset='utf-8'><title>Eptal-Analyzer Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#1f1f1f;color:#eee;padding:20px}} table{{border-collapse:collapse;width:100%;margin-bottom:16px}} th,td{{border:1px solid #444;padding:6px;font-size:12px;vertical-align:top}} th{{background:#333}} .warn{{color:#ffcc00}} .card{{background:#2a2a2a;padding:12px;border-radius:8px;margin-bottom:12px}}</style></head>
<body><h1>Eptal-Analyzer — отчёт</h1>
<div class='card'><p>Дата: {html_lib.escape(time.strftime('%Y-%m-%d %H:%M:%S'))}</p>
<p>Устройств: {len(hosts)} | Открытых портов: {ports_total} | Узлов с типичными рисковыми портами: {risky}</p>
<p>Шлюз: {html_lib.escape(gw_status)}</p>
<p class='warn'>Примечание: программа определяет симптомы недоступности, но не подтверждает физический обрыв кабеля.</p></div>
<h2>Сводка по ролям</h2><ul>{roles_html}</ul>
<h2>Риски (типичные порты)</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>Порты</th></tr></thead><tbody>{risks_html}</tbody></table>
<h2>Критичные узлы</h2><ul>{crit}</ul>
<h2>Устройства</h2><table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Role</th><th>OS</th><th>Open ports</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>События</h2><ul>{events}</ul></body></html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html_doc)
        self.statusBar().showMessage(f"Отчёт сохранён: {path}")

    def _history_dir(self):
        # Папка истории сканирований.
        path = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Eptal-Analyzer", "history")
        os.makedirs(path, exist_ok=True)
        return path

    def _save_scan_history(self, hosts):
        # Сохранение снимка сканирования для истории.
        import json
        entry = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "target": self.subnet_label.text().strip() if hasattr(self, "subnet_label") else "",
            "count": len(hosts),
            "hosts": hosts,
        }
        name = time.strftime("%Y%m%d-%H%M%S") + ".json"
        path = os.path.join(self._history_dir(), name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False, indent=2)
        files = sorted([
            p for p in os.listdir(self._history_dir())
            if p.endswith(".json") and p.lower() != "inventory.json"
        ])
        for old in files[:-30]:
            try:
                os.remove(os.path.join(self._history_dir(), old))
            except Exception:
                logging.getLogger(__name__).debug("Failed to remove old scan history: %s", old, exc_info=True)

    def _show_history(self):
        # Показ истории сканирований и сравнение последних снимков.
        import json
        files = sorted([
            p for p in os.listdir(self._history_dir())
            if p.endswith(".json") and p.lower() != "inventory.json"
        ], reverse=True)
        if not files:
            QMessageBox.information(self, "История", "История сканирований пуста.")
            return
        lines = []
        for fn in files[:20]:
            try:
                with open(os.path.join(self._history_dir(), fn), "r", encoding="utf-8") as f:
                    data = json.load(f)
                lines.append(f"{data.get('ts','')} | {data.get('target','')} | устройств: {data.get('count',0)} | {fn}")
            except Exception:
                logging.getLogger(__name__).debug("Failed to read history entry: %s", fn, exc_info=True)
                lines.append(fn)
        box = QMessageBox(self)
        box.setWindowTitle("История сканирований")
        box.setIcon(QMessageBox.Icon.Information)
        box.setText("Последние сканирования")
        box.setInformativeText("\n".join(lines))
        diff_last_btn = box.addButton("Сравнить 2 последних", QMessageBox.ButtonRole.ActionRole)
        diff_pick_btn = box.addButton("Выбрать 2 файла", QMessageBox.ButtonRole.ActionRole)
        clear_btn = box.addButton("Очистить историю", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton(QMessageBox.StandardButton.Ok)
        box.exec()
        clicked = box.clickedButton()
        if clicked == diff_last_btn:
            self._show_history_diff(files[0], files[1]) if len(files) >= 2 else QMessageBox.information(self, "Сравнение", "Нужно минимум два снимка.")
        elif clicked == diff_pick_btn:
            self._show_history_diff_picker(files)
        elif clicked == clear_btn:
            self._clear_scan_history()

    def _clear_scan_history(self):
        # Очистка файлов истории сканирований (без удаления inventory.json).
        confirm = QMessageBox.question(
            self,
            "Очистить историю",
            "Удалить историю сканирований? Метки и заметки инвентаря останутся.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        hist_dir = self._history_dir()
        removed = 0
        for fn in os.listdir(hist_dir):
            if not fn.lower().endswith(".json"):
                continue
            if fn.lower() == "inventory.json":
                continue
            try:
                os.remove(os.path.join(hist_dir, fn))
                removed += 1
            except Exception:
                logging.getLogger(__name__).debug("Failed to remove history file: %s", fn, exc_info=True)
        self.statusBar().showMessage(f"История очищена: удалено файлов {removed}.")

    def _show_history_diff_picker(self, files):
        # Выбор двух снимков истории для сравнения.
        if len(files) < 2:
            QMessageBox.information(self, "Сравнение", "Нужно минимум два снимка.")
            return
        f1, ok1 = QInputDialog.getItem(self, "Сравнение", "Новый снимок:", files, 0, False)
        if not ok1:
            return
        f2, ok2 = QInputDialog.getItem(self, "Сравнение", "Старый снимок:", files, min(1, len(files)-1), False)
        if not ok2:
            return
        self._show_history_diff(f1, f2)

    def _show_history_diff(self, newer_fn, older_fn):
        # Сравнение двух снимков истории.
        import json
        def load(fn):
            with open(os.path.join(self._history_dir(), fn), "r", encoding="utf-8") as f:
                return json.load(f)
        try:
            newer = load(newer_fn)
            older = load(older_fn)
        except Exception as e:
            QMessageBox.warning(self, "Сравнение", f"Ошибка чтения истории: {e}")
            return
        new_ips = {h.get("ip") for h in newer.get("hosts", []) if h.get("ip")}
        old_ips = {h.get("ip") for h in older.get("hosts", []) if h.get("ip")}
        appeared = sorted(new_ips - old_ips)
        disappeared = sorted(old_ips - new_ips)
        text = [
            f"Новый: {newer.get('ts')} ({newer.get('count')}) [{newer_fn}]",
            f"Старый: {older.get('ts')} ({older.get('count')}) [{older_fn}]",
            "",
            f"Появились ({len(appeared)}): {', '.join(appeared) or 'нет'}",
            f"Пропали ({len(disappeared)}): {', '.join(disappeared) or 'нет'}",
        ]
        QMessageBox.information(self, "Сравнение сканирований", "\n".join(text))

    def _check_dependencies(self):
        # Проверка зависимостей Windows при запуске.
        checks = self._collect_diagnostics()
        issues = [name for name, status, _ in checks if status not in ("OK",)]
        if issues:
            msg = "Проверка окружения: проблемы — " + ", ".join(issues)
            self.statusBar().showMessage(msg)
            logging.getLogger(__name__).warning(msg)
        else:
            self.statusBar().showMessage("Окружение: Nmap, Npcap, права администратора — OK")
            logging.getLogger(__name__).info("Dependency check OK")

    def _apply_theme(self):
        # Глобальная тема интерфейса: тёмно-серые тона, белый текст, скруглённые элементы.
        self.setStyleSheet(APP_THEME_QSS)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setSpacing(0)
        root_layout.setContentsMargins(0, 0, 0, 0)

        root_layout.addWidget(self._build_toolbar())

        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setSpacing(0)
        body_layout.setContentsMargins(0, 0, 0, 0)

        body_layout.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        self.stack.addWidget(self._build_home_page())
        self.stack.addWidget(self._build_scan_page())
        self.stack.addWidget(self._build_graph_page())
        self.stack.addWidget(self._build_attackSurface_page())
        self.stack.addWidget(self._build_trafficAnalyzer_page())
        self.stack.addWidget(self._build_diagnostics_page())
        self.stack.addWidget(self._build_inventory_page())
        self.stack.addWidget(self._build_monitoring_page())
        self.stack.addWidget(self._build_audit_page())
        self.stack.addWidget(self._build_settings_page())
        self.stack.addWidget(self._build_help_page())
        body_layout.addWidget(self.stack, stretch=1)

        root_layout.addWidget(body, stretch=1)

        # Строка состояния приложения.
        self.statusBar().showMessage("Готово.")
        self.statusBar().setStyleSheet("color: #d0d0d0; font-size: 11px;")

    def _build_sidebar(self):
        sidebar = QWidget()
        sidebar.setFixedWidth(56)
        sidebar.setStyleSheet("""
            QWidget {
                background-color: #252526;
                border-right: 1px solid #3c3c3c;
            }
        """)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(4, 8, 4, 8)
        layout.setSpacing(4)

        assets = os.path.join(os.path.dirname(__file__), "../img", "icons")

        def make_btn(icon_file, tooltip):
            icon_path = os.path.join(assets, icon_file)
            btn = QPushButton()
            btn.setIcon(load_colored_svg(icon_path, "#666666", size=22))
            btn.setIconSize(QSize(20, 20))
            btn.setToolTip(tooltip)
            btn.setFixedSize(48, 48)
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    border: none;
                    border-radius: 8px;
                }
            """)
            return btn, icon_path

        # Кнопки навигации по разделам приложения.
        btn_home,  path_home  = make_btn("home.svg",     "Главная: обзор сети, список найденных устройств и быстрые действия")
        btn_scan,  path_scan  = make_btn("eye.svg", "Сканирование портов: проверка открытых портов и сервисов выбранной цели")
        btn_graph, path_graph = make_btn("network2.svg",    "Карта сети: графическая топология обнаруженных устройств")
        btn_attack, path_attack = make_btn("attack.svg", "Поверхность атаки: открытые сервисы, риски и найденные уязвимости")
        btn_traffic, path_traffic = make_btn("traffic.svg", "Анализ трафика: захват и просмотр сетевых пакетов в реальном времени")
        btn_diag, path_diag = make_btn("diagnostics.svg", "Диагностика сети: адаптер, Wi-Fi, DHCP/DNS, шлюз, интернет, MTU")
        btn_inv, path_inv = make_btn("inventory.svg", "Журнал и инвентарь: история устройств, изменения, метки и уведомления")
        btn_mon, path_mon = make_btn("monitoring.svg", "Мониторинг доступности: шлюз, критичные узлы, история проверок")
        btn_audit, path_audit = make_btn("audit.svg", "Аудит безопасности: риски, порты, уязвимости, IoT/камеры")
        btn_settings, path_settings = make_btn("settings.svg", "Настройки: параметры программы и язык интерфейса")
        btn_help, path_help = make_btn("help.svg", "Справка: полное руководство по всем функциям программы")

        self.nav_btns = [
            (btn_home,  path_home),
            (btn_scan,  path_scan),
            (btn_graph, path_graph),
            (btn_attack, path_attack),
            (btn_traffic, path_traffic),
            (btn_diag, path_diag),
            (btn_inv, path_inv),
            (btn_mon, path_mon),
            (btn_audit, path_audit),
            (btn_settings, path_settings),
            (btn_help, path_help),
        ]

        def navigate(index):
            self.stack.setCurrentIndex(index)
            self._set_active_nav(index)
            if index == 6 and hasattr(self, "_refresh_inventory_page"):
                self._refresh_inventory_page()
            if index == 7 and hasattr(self, "_refresh_monitoring_page"):
                self._refresh_monitoring_page()
            if index == 8 and hasattr(self, "_refresh_audit_page"):
                self._refresh_audit_page()

        btn_home.clicked.connect(lambda: navigate(0))
        btn_scan.clicked.connect(lambda: navigate(1))
        btn_graph.clicked.connect(lambda: navigate(2))
        btn_attack.clicked.connect(lambda: navigate(3))
        btn_traffic.clicked.connect(lambda: navigate(4))
        btn_diag.clicked.connect(lambda: navigate(5))
        btn_inv.clicked.connect(lambda: navigate(6))
        btn_mon.clicked.connect(lambda: navigate(7))
        btn_audit.clicked.connect(lambda: navigate(8))
        btn_settings.clicked.connect(lambda: navigate(9))
        btn_help.clicked.connect(lambda: navigate(10))

        for btn, path in self.nav_btns:
            layout.addWidget(btn)

        self._set_active_nav(0)

        layout.addStretch()
        return sidebar

    def _set_active_nav(self, index):
        for i, (btn, path) in enumerate(self.nav_btns):
            # Подсветка активного раздела в боковой навигации.
            active = i == index
            color = "#79a7ff" if active else "#9a9a9a"
            btn.setIcon(load_colored_svg(path, color))
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {'#333333' if active else 'transparent'};
                    border: none;
                    border-radius: 10px;
                }}
            """)

    def _toggle_language(self):
        # Переключение языка интерфейса RU/EN.
        new_lang = "en" if self.i18n.lang == "ru" else "ru"
        self.i18n.set_lang(new_lang)
        self.settings.setValue("language", new_lang)
        self.apply_language()

    def apply_language(self):
        # Применение текущего языка к основным элементам интерфейса.
        t = self.i18n.t
        if hasattr(self, "scan_button"):
            self.scan_button.setText(t("btn_scan"))
        if hasattr(self, "btn_open_log"):
            self.btn_open_log.setText(t("btn_open_log"))
        if hasattr(self, "btn_diagnostics"):
            self.btn_diagnostics.setText(t("btn_diagnostics"))
        if hasattr(self, "btn_events"):
            self.btn_events.setText(t("btn_events"))
        if hasattr(self, "btn_report"):
            self.btn_report.setText(t("btn_report"))
        if hasattr(self, "btn_history"):
            self.btn_history.setText(t("btn_history"))
        if hasattr(self, "btn_critical"):
            self.btn_critical.setText(t("btn_critical"))
        nav_keys = ["nav_home","nav_scan","nav_graph","nav_attack","nav_traffic","nav_diag","nav_inv","nav_mon","nav_audit","nav_settings","nav_help"]
        if hasattr(self, "nav_btns"):
            for i, (btn, _path) in enumerate(self.nav_btns):
                if i < len(nav_keys):
                    btn.setToolTip(t(nav_keys[i]))
        for attr, key in [("settings_title_label","settings_title"),("settings_lang_label","settings_language"),("settings_lang_hint","settings_language_hint"),("home_title_label","home_title"),("scan_title_label","scan_title"),("graph_title_label","graph_title"),("attack_title_label","attack_title"),("traffic_title_label","traffic_title"),("diag_title_label","diag_title"),("inv_title_label","inv_title"),("mon_title_label","mon_title"),("audit_title_label","audit_title"),("help_title_label","help_title")]:
            w = getattr(self, attr, None)
            if w is not None:
                w.setText(t(key))
        if hasattr(self, "lang_combo"):
            idx = self.lang_combo.findData(self.i18n.lang)
            if idx >= 0 and self.lang_combo.currentIndex() != idx:
                self.lang_combo.blockSignals(True)
                self.lang_combo.setCurrentIndex(idx)
                self.lang_combo.blockSignals(False)
        # Общие кнопки
        for attr, key in [("btn_start_capture","start"),("btn_stop_capture","stop"),("btn_clear_capture","clear"),("btn_ta_export","export"),("btn_ta_pcap","PCAP"),("btn_scan","btn_scan"),("scan_button","btn_scan")]:
            w=getattr(self,attr,None)
            if w is not None and hasattr(w,'setText'):
                w.setText(t(key))
        # Заголовки таблиц
        def _set_headers(tbl, keys):
            w = getattr(self, tbl, None)
            if w is not None and hasattr(w, 'setHorizontalHeaderLabels'):
                w.setHorizontalHeaderLabels([t(k) for k in keys])
        _set_headers('inventory_table', ["col_ip","col_mac","col_name","col_first_seen","col_last_seen","col_tag","col_note"])
        _set_headers('mon_table', ["col_time","col_type","col_target","col_status_details"])
        _set_headers('table', ["col_ip","col_mac","col_vendor","col_hostname"])
        _set_headers('as_history', [self.i18n.t("target").upper(), self.i18n.t("col_risk")])
        if hasattr(self, 'as_history') and self.as_history is not None:
            self.as_history.setHorizontalHeaderLabels([t("target").upper(), t("col_risk")])
        _set_headers('as_ports_table', ["col_port","col_proto","col_service","col_version","col_risk"])
        _set_headers('as_cve_table', ["col_cve","col_cvss","col_port","col_service","col_details"])
        _set_headers('ta_device_list', ["col_ip", "packets"])
        if hasattr(self, 'ta_table') and self.ta_table is not None:
            self.ta_table.setHorizontalHeaderLabels(["#", t("col_time_short"), t("col_src"), t("col_dst"), t("col_proto"), t("col_port_short"), t("col_size")])
        # Заголовки/подписи справки
        if hasattr(self, "help_title_label"):
            self.help_title_label.setText("Справка по функциям Eptal-Analyzer" if self.i18n.lang == "ru" else "Eptal-Analyzer Help Guide")
        if hasattr(self, "help_subtitle_label"):
            self.help_subtitle_label.setText(self.i18n.t("help_subtitle"))
        if hasattr(self, "_populate_help_page"):
            self._populate_help_page()
        # Граф/инвентарь/мониторинг подписи
        if hasattr(self, 'graph_view') and getattr(self, 'graph_ready', False):
            try:
                self.graph_view.page().runJavaScript(f"setGraphLang('{self.i18n.lang}')")
            except Exception:
                pass
        for attr, key in [("graph_header_label","graph_header"),("btn_live","graph_live"),("btn_monitor","graph_monitor"),("inv_hint_label","inv_hint"),("btn_inv_tag","inv_tag"),("btn_inv_note","inv_note"),("btn_inv_clear","inv_clear"),("btn_inv_refresh","inv_refresh"),("btn_mon_clear","mon_clear"),("btn_mon_export","mon_export"),("btn_mon_refresh","mon_refresh"),("btn_audit_export","export"),("btn_audit_clear","clear"),("btn_audit_refresh","refresh"),("scan_target_label","scan_target_label"),("scan_saved_target_label","scan_saved_target"),("scan_profile_label","scan_profile_label")]:
            w = getattr(self, attr, None)
            if w is not None and hasattr(w, 'setText'):
                w.setText(t(key))
        # Профили сканирования
        if hasattr(self, 'scan_profile') and self.scan_profile is not None:
            cur = self.scan_profile.currentIndex()
            items = [("scan_profile_manual",[]),("scan_profile_fast",["-F","-T4","--open"]),("scan_profile_normal",["-sV","-T3","--open"]),("scan_profile_deep",["-sV","-sC","-O","-T4","--open"])]
            self.scan_profile.blockSignals(True)
            self.scan_profile.clear()
            for k, data in items:
                self.scan_profile.addItem(t(k), userData=data)
            if 0 <= cur < len(items):
                self.scan_profile.setCurrentIndex(cur)
            self.scan_profile.blockSignals(False)
        if hasattr(self, 'target_profile_combo') and self.target_profile_combo is not None:
            cur_data = self.target_profile_combo.currentData()
            self.target_profile_combo.blockSignals(True)
            self.target_profile_combo.clear()
            self.target_profile_combo.addItem(t("scan_select_target"), userData=None)
            for prof in getattr(self, '_target_profiles', []):
                self.target_profile_combo.addItem(f"{prof['name']} — {prof['target']}", userData=prof)
            idx = 0
            if isinstance(cur_data, dict):
                for i in range(self.target_profile_combo.count()):
                    d = self.target_profile_combo.itemData(i)
                    if isinstance(d, dict) and d.get('name') == cur_data.get('name'):
                        idx = i
                        break
            self.target_profile_combo.setCurrentIndex(idx)
            self.target_profile_combo.blockSignals(False)
        self.statusBar().showMessage(t("lang_switched"))

    def _build_toolbar(self):
        toolbar = QWidget()
        toolbar.setFixedHeight(56)
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(16, 0, 16, 0)

        title = QLabel("Eptal-Analyzer")
        title.setObjectName("title_label")

        self.subnet_label = QLineEdit()
        self.subnet_label.setObjectName("subnet_label")
        self.subnet_label.setPlaceholderText("подсеть, IP или диапазон")
        self.subnet_label.setFixedWidth(210)
        self.subnet_label.setStyleSheet("""
                QLineEdit#subnet_label {
                    background-color: transparent;
                    color: #888888;
                    border: none;
                    border-bottom: 1px solid transparent;
                    font-size: 12px;
                }
                QLineEdit#subnet_label:focus {
                    color: #ffffff;
                    border-bottom: 1px solid #5a5a5a;
                }
        """)

        self.iface_selector = QComboBox()
        self.iface_selector.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.iface_selector.setStyleSheet("""
                QComboBox {
                    background-color: #2b2b2b;
                    color: #aaaaaa;
                    border: 1px solid #222222;
                    padding: 4px 10px;
                    font-size: 11px;
                    border-radius: 8px;
            }
                QComboBox:hover {
                    border-color: #00f999;
                    color: #ffffff;
                }
                QComboBox QAbstractItemView {
                    background-color: #2b2b2b;
                    color: #aaaaaa;
                    selection-background-color: #ffffff;
                    selection-color: #ffffff;
                    border: 1px solid #3c3c3c;
                }
        """)

        self._load_interfaces()
        self.iface_selector.currentIndexChanged.connect(self._on_iface_changed)

        # Кнопка запуска сканирования сети.
        self.scan_button = QPushButton(self.i18n.t("btn_scan"))
        self.scan_button.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.scan_button.clicked.connect(self._start_scan)

        # Круговой индикатор загрузки рядом с кнопкой сканирования.
        self.scan_progress = SpinnerWidget(size=22)

        # Кнопка открытия лога приложения.
        self.btn_open_log = QPushButton(self.i18n.t("btn_open_log"))
        self.btn_open_log.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_open_log.setToolTip("Открыть файл лога")
        self.btn_open_log.clicked.connect(self._open_log)
        # Кнопка диагностики зависимостей и окружения.
        self.btn_diagnostics = QPushButton(self.i18n.t("btn_diagnostics"))
        self.btn_diagnostics.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_diagnostics.setToolTip("Проверить Nmap, Npcap, права администратора")
        self.btn_diagnostics.clicked.connect(self._show_diagnostics)
        # Кнопка журнала событий доступности.
        self.btn_events = QPushButton(self.i18n.t("btn_events"))
        self.btn_events.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_events.setToolTip("Журнал изменений доступности устройств")
        self.btn_events.clicked.connect(self._show_events)
        # Кнопка экспорта HTML-отчёта.
        self.btn_report = QPushButton(self.i18n.t("btn_report"))
        self.btn_report.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_report.setToolTip("Экспортировать HTML-отчёт")
        self.btn_report.clicked.connect(self._export_report)
        # Кнопка истории сканирований.
        self.btn_history = QPushButton(self.i18n.t("btn_history"))
        self.btn_history.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_history.setToolTip("История сканирований")
        self.btn_history.clicked.connect(self._show_history)
        # Кнопка управления критичными узлами.
        self.btn_critical = QPushButton(self.i18n.t("btn_critical"))
        self.btn_critical.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_critical.setToolTip("Список критичных узлов для мониторинга доступности")
        self.btn_critical.clicked.connect(self._manage_critical_hosts)

        # Компактный стиль для служебных кнопок панели (кроме СКАНИРОВАТЬ).
        for b in [self.btn_diagnostics, self.btn_open_log, self.btn_events, self.btn_report, self.btn_history, self.btn_critical]:
            b.setStyleSheet("QPushButton { padding: 4px 8px; font-size: 11px; border-radius: 6px; }")

        layout.addWidget(title)
        layout.addSpacing(16)
        layout.addWidget(self.subnet_label)
        layout.addSpacing(12)
        layout.addWidget(self.iface_selector)
        layout.addSpacing(12)
        layout.addWidget(self.btn_diagnostics)
        layout.addSpacing(8)
        layout.addWidget(self.btn_open_log)
        layout.addSpacing(8)
        layout.addWidget(self.btn_events)
        layout.addSpacing(8)
        layout.addWidget(self.btn_report)
        layout.addSpacing(8)
        layout.addWidget(self.btn_history)
        layout.addSpacing(8)
        layout.addWidget(self.btn_critical)
        layout.addStretch()
        layout.addWidget(self.scan_progress)
        layout.addSpacing(10)
        layout.addWidget(self.scan_button)

        return toolbar

    def _load_interfaces(self):
        interfaces = get_network_interfaces()
        self.interfaces = interfaces

        self.iface_selector.blockSignals(True)
        self.iface_selector.clear()

        for iface in interfaces:
            self.iface_selector.addItem(f"{iface['name']} {iface['ip']}", userData=iface)

        self.iface_selector.blockSignals(False)

    def _on_iface_changed(self,index):
        iface = self.iface_selector.itemData(index)
        if not iface:
            return
        try:
            self.subnet_label.setText(get_local_subnet(iface["name"]))
        except Exception:
            logging.getLogger(__name__).debug("Failed to get local subnet for interface", exc_info=True)
            self.subnet_label.clear()

    def _resolve_subnet(self):
        manual = self.subnet_label.text().strip()
        if manual:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$", manual):
                return manual
            try:
                return str(ipaddress.ip_network(manual, strict=False))
            except ValueError:
                pass
            try:
                ipaddress.ip_address(manual)
                return manual
            except ValueError:
                pass

        iface = self.iface_selector.currentData()
        if not iface:
            return None
        try:
            return get_local_subnet(iface["name"])
        except Exception:
            logging.getLogger(__name__).debug("Failed to get local subnet", exc_info=True)
            return None

    def _build_home_page(self):

        home = QWidget()
        layout = QVBoxLayout(home)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_table())
        splitter.addWidget(self._build_detail_panel())
        splitter.setSizes([800, 400])
        splitter.setStyleSheet("QSplitter::handle { background-color: #3c3c3c; }")
        layout.addWidget(splitter, stretch=1)

        return home

    def _build_scan_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0,0,0,0)

        layout.addWidget(self._build_scan_options())
        layout.addWidget(self._build_scan_output(), stretch=1)

        self.scan_button.clicked.connect(
            lambda: (self.stack.setCurrentIndex(0), self._set_active_nav(0))
        )

        return page

    def _build_scan_options(self):
        scroll = QScrollArea()
        scroll.setFixedWidth(360)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12,12,12,12)
        layout.setSpacing(6)

        self.scan_target_label = QLabel(self.i18n.t("scan_target_label"))
        self.scan_target_label.setStyleSheet("""
                color: #ffffff;
                font-size: 11px;
                letter-spacing: 2px;
        """)
        layout.addWidget(self.scan_target_label)

        self.scan_target = QLineEdit()
        self.scan_target.setPlaceholderText("192.168.1.1")
        self.scan_target.setStyleSheet("""
            QLineEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                padding: 6px;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                border-radius: 8px;
            }
            QLineEdit:focus {
                border: 1px solid #909090;
            }
        """)
        layout.addWidget(self.scan_target)
        layout.setSpacing(8)

        # Сохранённые цели сканирования.
        self.scan_saved_target_label = QLabel(self.i18n.t("scan_saved_target"))
        self.scan_saved_target_label.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(self.scan_saved_target_label)
        tp_row = QHBoxLayout()
        self.target_profile_combo = QComboBox()
        self.target_profile_combo.currentIndexChanged.connect(self._apply_target_profile)
        tp_row.addWidget(self.target_profile_combo, stretch=1)
        btn_save_tp = QPushButton(self.i18n.t("save_short"))
        btn_save_tp.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_save_tp.clicked.connect(self._save_target_profile)
        tp_row.addWidget(btn_save_tp)
        btn_del_tp = QPushButton(self.i18n.t("delete_short"))
        btn_del_tp.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_del_tp.clicked.connect(self._delete_target_profile)
        tp_row.addWidget(btn_del_tp)
        layout.addLayout(tp_row)
        self._refresh_target_profiles()
        layout.addSpacing(8)

        # Профиль сканирования: быстрый набор типовых флагов Nmap.
        self.scan_profile_label = QLabel(self.i18n.t("scan_profile_label"))
        self.scan_profile_label.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(self.scan_profile_label)
        self.scan_profile = QComboBox()
        self.scan_profile.addItem(self.i18n.t("scan_profile_manual"), userData=[])
        self.scan_profile.addItem(self.i18n.t("scan_profile_fast"), userData=["-F", "-T4", "--open"])
        self.scan_profile.addItem(self.i18n.t("scan_profile_normal"), userData=["-sV", "-T3", "--open"])
        self.scan_profile.addItem(self.i18n.t("scan_profile_deep"), userData=["-sV", "-sC", "-O", "-T4", "--open"])
        self.scan_profile.currentIndexChanged.connect(self._apply_scan_profile)
        layout.addWidget(self.scan_profile)
        layout.addSpacing(8)

        self._scan_checks = {}
        sections = {
        self.i18n.t("scan_section_type"): [
            ("-F", "Fast scan"),
            ("-sS", "SYN scan"),
            ("-sT", "TCP connect"),
            ("-sU", "UDP scan"),
            ("-sN", "NULL scan"),
            ("-sX", "Xmas scan"),
            ("-p-", "All ports"),
            ("-A", "Aggressive"),
            ("-Pn", "No ping"),
        ],
        self.i18n.t("scan_section_discovery"): [
            ("-sV", "Service version"),
            ("-O", "OS detection"),
            ("--osscan-guess", "OS guess"),
        ],
        "СКРИПТЫ": [
            ("-sC", "Default scripts"),
            ("--script banner", "Banner grab"),
            ("--script safe", "Safe scripts"),
            ("--script vuln", "Vuln scan"),
            ("--script vulners", "Vulners CVE"),
            ("--script malware", "Malware detect"),
            ("--script discovery", "Discovery"),
            ("--script http-enum", "HTTP enum"),
            ("--script http-headers", "HTTP headers"),
            ("--script http-methods", "HTTP methods"),
            ("--script ssl-cert", "SSL cert"),
            ("--script ssl-enum-ciphers", "SSL ciphers"),
            ("--script smb-enum-shares", "SMB shares"),
            ("--script smb-enum-users", "SMB users"),
            ("--script dns-brute", "DNS brute"),
            ("--script ftp-anon", "FTP anon"),
            ("--script ssh-auth-methods", "SSH auth"),
        ],
        self.i18n.t("scan_section_output"): [
            ("--open", "Show open only"),
            ("-v", "Verbose"),
            ("--reason", "Show reason"),
        ],
        self.i18n.t("scan_section_timing"): [
            ("-T1", "Sneaky (slow)"),
            ("-T2", "Polite"),
            ("-T3", "Normal"),
            ("-T4", "Aggressive"),
            ("-T5", "Insane (fast)"),
        ],
    }

        for section_name, options in sections.items():
            sep = QWidget()
            sep.setFixedHeight(1)
            sep.setStyleSheet("background-color: #3c3c3c;")
            layout.addWidget(sep)
            layout.addSpacing(4)

            sec_label = QLabel(section_name)
            sec_label.setStyleSheet("""
                    color: #ffffff;
                    font-size: 11px;
                    letter-spacing: 2px;
            """)
            layout.addWidget(sec_label)
            layout.addSpacing(2)

            for flag, description in options:
                cb = QCheckBox(f"{description}")
                cb.setFocusPolicy(Qt.FocusPolicy.NoFocus)
                cb.setToolTip(flag)
                cb.setStyleSheet("""
                    QCheckBox {
                        color: #aaaaaa;
                        font-size: 12px;
                        spacing: 6px;
                    }
                    QCheckBox:hover {
                        color: #ffffff;
                    }
                    QCheckBox::indicator {
                        width: 12px;
                        height: 12px;
                        border: 1px solid #c0c0c0;
                        background-color: #111;
                    }
                    QCheckBox::indicator:checked {
                        background-color: #ffffff;
                        border: 1px solid #909090;
                    }
            """)
                self._scan_checks[flag] = cb
                layout.addWidget(cb)
            layout.addSpacing(4)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #3c3c3c;")
        layout.addWidget(sep)
        layout.addSpacing(4)

        custom_label = QLabel("СВОИ ФЛАГИ")
        custom_label.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(custom_label)

        self.custom_flags = QLineEdit()
        self.custom_flags.setPlaceholderText("-p 80,443 --script http-title")
        self.custom_flags.setStyleSheet("""
                QLineEdit {
                    background-color: #2b2b2b;
                    color: #ffffff;
                    border: 1px solid #3c3c3c;
                    padding: 6px;
                    font-family: 'Consolas', 'JetBrains Mono', monospace;
                    font-size: 11px;
                    border-radius: 8px;
            }
                QLineEdit:focus {
                    border: 1px solid #909090;
                }
        """)
        layout.addWidget(self.custom_flags)
        layout.addSpacing(12)

        # Кнопка запуска сканирования портов/цели.
        self.btn_run_scan = QPushButton(self.i18n.t("run_scan"))
        self.btn_run_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)
        layout.addWidget(self.btn_run_scan)

        # Кнопка экспорта результатов сканирования.
        self.btn_export_scan = QPushButton(self.i18n.t("export"))
        self.btn_export_scan.setStyleSheet("")
        self.btn_export_scan.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_scan.setDisabled(True)
        self.btn_export_scan.clicked.connect(self._export_scan)

        layout.addSpacing(6)
        layout.addWidget(self.btn_export_scan)

        layout.addStretch()
        scroll.setWidget(container)
        return scroll

    def _export_scan(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Eptal-Analyzer scan",
            "scan.txt",
            "Text Files (*.txt);;All Files(*)"
        )
        if not path:
            return

        with open(path,"w") as f:
            f.write(self.scan_output.toPlainText())

    def _build_scan_output(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        self.scan_cmd_label = QLabel("// нет активного сканирования.")
        self.scan_cmd_label.setStyleSheet("""
                background-color: #252526;
                color: #d0d0d0;
                font-size: 11px;
                padding: 8px 12px;
                border-bottom: 1px solid #3c3c3c;
        """)
        layout.addWidget(self.scan_cmd_label)

        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        self.scan_output.setStyleSheet("""
                QTextEdit {
                    background-color: #262626;
                    color: #ffffff;
                    border: none;
                    font-family: 'Consolas', 'JetBrains Mono', monospace;
                    font-size: 12px;
                    padding: 12px;
                    border-radius: 8px;
            }
        """)
        self.scan_output.setPlaceholderText("// выберите параметры и запустите сканирование...")
        layout.addWidget(self.scan_output, stretch=1)
        return container

    def _apply_scan_profile(self):
        # Применение выбранного профиля сканирования к чекбоксам.
        flags = self.scan_profile.currentData() or []
        if not flags:
            return
        for flag, cb in self._scan_checks.items():
            cb.setChecked(flag in flags)

    def _remember_target(self, target):
        # Сохранение недавних целей сканирования.
        target = (target or "").strip()
        if not target:
            return
        if target in self._recent_targets:
            self._recent_targets.remove(target)
        self._recent_targets.insert(0, target)
        self._recent_targets = self._recent_targets[:20]
        self.settings.setValue("recent_targets", self._recent_targets)
        if hasattr(self, "scan_target"):
            self.scan_target.setCompleter(QCompleter(self._recent_targets, self))

    def _refresh_target_profiles(self):
        # Обновление списка сохранённых целей.
        if not hasattr(self, "target_profile_combo"):
            return
        self.target_profile_combo.blockSignals(True)
        self.target_profile_combo.clear()
        self.target_profile_combo.addItem(self.i18n.t("scan_select_target"), userData=None)
        for p in self._target_profiles:
            self.target_profile_combo.addItem(f"{p['name']} — {p['target']}", userData=p)
        self.target_profile_combo.blockSignals(False)

    def _apply_target_profile(self):
        data = self.target_profile_combo.currentData()
        if isinstance(data, dict) and hasattr(self, "scan_target"):
            self.scan_target.setText(str(data.get("target", "")))

    def _save_target_profile(self):
        # Сохранение именованной цели.
        target = self.scan_target.text().strip() if hasattr(self, "scan_target") else ""
        if not target:
            self.statusBar().showMessage("Нет цели для сохранения.")
            return
        if not is_valid_target(target):
            self.statusBar().showMessage("Некорректная цель: IP, CIDR, диапазон или hostname.")
            return
        name, ok = QInputDialog.getText(self, "Сохранить цель", "Имя цели:")
        if not ok or not name.strip():
            return
        entry = {"name": name.strip(), "target": target}
        self._target_profiles = [p for p in self._target_profiles if p.get("name") != entry["name"]]
        self._target_profiles.insert(0, entry)
        self._target_profiles = self._target_profiles[:30]
        self.settings.setValue("target_profiles", self._target_profiles)
        self._refresh_target_profiles()

    def _delete_target_profile(self):
        # Удаление выбранной сохранённой цели.
        data = self.target_profile_combo.currentData()
        if not isinstance(data, dict):
            return
        self._target_profiles = [p for p in self._target_profiles if p.get("name") != data.get("name")]
        self.settings.setValue("target_profiles", self._target_profiles)
        self._refresh_target_profiles()

    def _run_nmap_scan(self):
        # Запуск Nmap через очередь задач.
        self._enqueue_task("Nmap сканирование", self._do_nmap_scan)

    def _do_nmap_scan(self):
        if hasattr(self, "action_worker") and self.action_worker.isRunning():
            self.scan_output.append("// error: другая команда уже выполняется")
            self._finish_task("Nmap сканирование")
            return
        target = self.scan_target.text().strip()
        if not target:
            self.scan_output.append("// error: no target specified")
            self._finish_task("Nmap сканирование")
            return
        if not is_valid_target(target):
            self.scan_output.append("// error: некорректная цель (IP, CIDR, диапазон или hostname)")
            self._finish_task("Nmap сканирование")
            return
        self._remember_target(target)

        cmd = ["nmap"]
        risky_flags = {"-A", "--script vuln", "--script malware", "-sU", "-p-"}
        selected_risky = []
        for flag, cb in self._scan_checks.items():
            if cb.isChecked():
                cmd.extend(flag.split())
                if flag in risky_flags:
                    selected_risky.append(flag)

        custom = self.custom_flags.text().strip()
        if custom:
            cmd.extend(custom.split())

        cmd.append(target)
        if selected_risky:
            self.scan_output.append(f"// предупреждение: выбраны агрессивные/тяжёлые опции: {', '.join(selected_risky)}")

        self.scan_cmd_label.setText("// " + " ".join(cmd))
        self.scan_cmd_label.setStyleSheet("""
                background-color: #252526;
                color: #ffffff;
                font-size: 11px;
                padding: 8px 12px;
                border-bottom: 1px solid #3c3c3c;
        """)
        self.scan_output.clear()
        self.scan_output.append(f"// {''.join(cmd)}\n")

        self.btn_run_scan.setText("STOP")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._stop_nmap_scan)

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.scan_output.append)
        self.action_worker.finished.connect(self._on_nmap_finished)
        self.action_worker.start()

    def _stop_nmap_scan(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            try:
                self.action_worker.finished.disconnect()
            except Exception:
                logging.getLogger(__name__).debug("Failed to disconnect action worker", exc_info=True)
            self.action_worker.stop()
            self.action_worker.wait(3000)
        self.scan_output.append("\n// Interrupted.")
        self.btn_export_scan.setDisabled(True)
        self.btn_run_scan.setText("RUN SCAN")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)
        self._finish_task("Nmap сканирование")

    def _on_nmap_finished(self):
        self.scan_output.append("\n// Done.")
        self.btn_export_scan.setDisabled(False)
        self.btn_run_scan.setText("RUN SCAN")
        self.btn_run_scan.clicked.disconnect()
        self.btn_run_scan.clicked.connect(self._run_nmap_scan)
        self._finish_task("Nmap сканирование")

    def _build_graph_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #252526; border-bottom: 1px solid #3c3c3c;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12,0,12,0)

        self.graph_header_label = QLabel(self.i18n.t("graph_header"))
        self.graph_header_label.setStyleSheet("color: #d0d0d0; font-size: 11px; padding-right: 10px; padding-left: 10px;")
        header_layout.addWidget(self.graph_header_label)
        header_layout.addSpacing(10)

        self.btn_export_graph = QComboBox()
        self.btn_export_graph.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_export_graph.addItem("EXPORT")
        self.btn_export_graph.addItem("CSV", userData="csv")
        self.btn_export_graph.addItem("PNG", userData="png")
        self.btn_export_graph.setFixedWidth(120)
        self.btn_export_graph.setStyleSheet("""
                QComboBox {
                    background-color: #2b2b2b;
                    color: #aaaaaa;
                    border: 1px solid #222222;
                    padding: 2px 8px;
                    font-size: 11px;
                    border-radius: 8px;
            }
                QComboBox:hover {
                    border-color: #ffffff;
                    color: #ffffff;
                }
                QComboBox QAbstractItemView {
                    background-color: #2b2b2b;
                    color: #aaaaaa;
                    selection-background-color: #ffffff;
                    selection-color: #ffffff;
                    border: 1px solid #3c3c3c;
                }
        """)
        self.btn_export_graph.currentIndexChanged.connect(self._export_graph)
        self.btn_export_graph.setDisabled(True)
        header_layout.addWidget(self.btn_export_graph)
        header_layout.addStretch()

        self.live_interval = QComboBox()
        self.live_interval.addItem("30s", userData=30)
        self.live_interval.addItem("60", userData=60)
        self.live_interval.addItem("120", userData=120)
        self.live_interval.setFixedWidth(70)
        self.live_interval.setDisabled(True)
        self.live_interval.setStyleSheet("""
            QComboBox {
                background-color: #2b2b2b;
                color: #d0d0d0;
                border: 1px solid #3c3c3c;
                padding: 2px 6px;
                font-size: 10px;
                border-radius: 8px;
            }
            QComboBox QAbstractItemView {
                background-color: #2b2b2b;
                color: #aaaaaa;
                selection-background-color: #ffffff22;
                selection-color: #ffffff;
            }
        """)
        header_layout.addWidget(self.live_interval)
        header_layout.addSpacing(10)

        # Кнопка включения автообновления карты.
        self.btn_live = QPushButton(self.i18n.t("graph_live"))
        self.btn_live.setFixedWidth(80)
        self.btn_live.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_live.setCheckable(True)
        self.btn_live.clicked.connect(self._toggle_live)
        self.btn_live.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #d0d0d0;
                border: 1px solid #c0c0c0;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
            QPushButton:checked {
                background-color: #003322;
                color: #ffffff;
                border: 1px solid #909090;
            }
            QPushButton:focus {
                outline: 0;
            }
        """)
        header_layout.addWidget(self.btn_live)

        header_layout.addSpacing(10)

        # Кнопка непрерывного мониторинга сети.
        self.btn_monitor = QPushButton(self.i18n.t("graph_monitor"))
        self.btn_monitor.setFixedWidth(110)
        self.btn_monitor.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_monitor.setCheckable(True)
        self.btn_monitor.clicked.connect(self._toggle_continuous_monitor)
        self.btn_monitor.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #d0d0d0;
                border: 1px solid #c0c0c0;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
            QPushButton:checked {
                background-color: #330022;
                color: #ff00aa;
                border: 1px solid #ff00aa;
            }
            QPushButton:focus {
                outline: 0;
            }
        """)
        header_layout.addWidget(self.btn_monitor)

        layout.addWidget(header)

        self.graph_view = QWebEngineView()
        self.graph_view.setStyleSheet("background-color: #0d0d0d;")
        self.graph_ready = False

        html_path = os.path.join(
            os.path.dirname(__file__), "assets", "graph.html"
        )
        self.graph_view.load(QUrl.fromLocalFile(html_path))
        self.graph_view.loadFinished.connect(self._on_graph_loaded)
        layout.addWidget(self.graph_view, stretch=1)

        return page

    def _toggle_continuous_monitor(self):
        if self.btn_monitor.isChecked():
            subnet = self._resolve_subnet()
            if not subnet:
                self.statusBar().showMessage("No subnet available for continuous monitoring.")
                self.btn_monitor.setChecked(False)
                return
            self._monitor_active = True
            iface = self.iface_selector.currentData()
            iface_name = iface["name"] if iface else None
            self.continuous_monitor = ContinuousMonitor()
            self.continuous_monitor.start(
                subnet=subnet,
                iface=iface_name,
                interval=60,
                callback=self._on_continuous_update
            )
            self.statusBar().showMessage("Continuous monitoring active — 60s refresh")
        else:
            self._monitor_active = False
            if self.continuous_monitor:
                self.continuous_monitor.stop()
                self.continuous_monitor = None
            self.statusBar().showMessage("Continuous monitoring stopped.")

    def _on_continuous_update(self, hosts):
        if hasattr(self, 'graph_view') and self.graph_ready:
            self._update_graph(hosts)
            self.last_hosts = hosts
            self.statusBar().showMessage(f"Continuous update — {len(hosts)} devices")

    def _toggle_live(self):
        if self.btn_live.isChecked():
            interval = self.live_interval.currentData() * 1000
            self.live_timer.start(interval)
            self.live_interval.setDisabled(False)
            self.statusBar().showMessage(f"Live monitoring active — refresh every {self.live_interval.currentText()}")
        else:
            self.live_timer.stop()
            self.live_interval.setDisabled(True)
            self.statusBar().showMessage("Live Monitoring Stopped.")

    def _live_scan(self):
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            return

        subnet = self._resolve_subnet()
        if not subnet:
            self.statusBar().showMessage("No subnet available for live scan.")
            return

        self.live_worker = ScanWorker(subnet)
        self.live_worker.finished.connect(self._on_live_scan_finished)
        self.live_worker.start()

    def _on_live_scan_finished(self, hosts):
        self._update_graph(hosts)
        events = self._record_scan_events(hosts)
        self.last_hosts = hosts
        msg = f"Live update — {len(hosts)} устройств — {self.live_interval.currentText()}"
        if events:
            msg += f" | событий: {len(events)}"
        self.statusBar().showMessage(msg)

    def _export_graph(self, index):
        if index == 0:
            return

        fmt = self.btn_export_graph.itemData(index)
        if not hasattr(self, 'last_hosts') or not self.last_hosts:
            self.statusBar().showMessage("No scan data to export.")
            self.btn_export_graph.setCurrentIndex(0)
            return

        if fmt == "csv":
            self._export_graph_csv()
        else:
            self._export_graph_png()

        self.btn_export_graph.setCurrentIndex(0)

    def _export_graph_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export csv graph",
            "graph.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip","mac","vendor","hostname"])
            writer.writeheader()
            writer.writerows(self.last_hosts)

        self.statusBar().showMessage(f"Graph (csv) exported in {path}")

    def _export_graph_png(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export png Graph",
            "graph.png",
            "PNG Images (*.png);;All Files(*)"
        )
        if not path:
            return

        pixmap = self.graph_view.grab()
        pixmap.save(path, "PNG")
        self.statusBar().showMessage(f"Graph (png) exported to {path}")

    def _on_graph_loaded(self, ok):
        self.graph_ready = True
        try:
            lang = getattr(getattr(self, 'i18n', None), 'lang', 'ru')
            self.graph_view.page().runJavaScript(f"setGraphLang('{lang}')")
        except Exception:
            pass
        if hasattr(self, '_pending_graph_data'):
            self._update_graph(self._pending_graph_data)

    def _ta_send_to_scan(self, item):
        row = item.row()
        ipR = self.ta_table.item(row, 2).text()
        ip = ipR.split(" ")[0]
        self.scan_target.setText(ip)
        self.stack.setCurrentIndex(1)
        self._set_active_nav(1)

    def _export_ta_csv(self):
        # Экспорт захваченных пакетов в CSV.
        if not self._ta_packets:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт трафика", "traffic.csv", "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                fieldnames = ["n", "time", "src", "dst", "proto", "port", "size", "info"]
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for p in self._ta_packets:
                    writer.writerow({
                        "n": p.get("n", ""),
                        "time": p.get("time", ""),
                        "src": p.get("src_label", p.get("src", "")),
                        "dst": p.get("dst_label", p.get("dst", "")),
                        "proto": p.get("proto", ""),
                        "port": p.get("port", ""),
                        "size": p.get("size", ""),
                        "info": p.get("info", ""),
                    })
            self.statusBar().showMessage(f"Трафик экспортирован: {path}")
        except Exception as e:
            logging.getLogger(__name__).debug("Failed to export traffic CSV", exc_info=True)
            QMessageBox.warning(self, "Экспорт трафика", f"Не удалось сохранить файл: {e}")

    def _build_trafficAnalyzer_page(self):
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # Левая панель со списком устройств в анализе трафика.
        left = QWidget()
        left.setFixedWidth(250)
        left.setStyleSheet("background-color: #252526; border-right: 1px solid #3c3c3c;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(8, 8, 8, 8)
        left_layout.setSpacing(4)

        dev_label = QLabel(self.i18n.t("devices"))
        dev_label.setStyleSheet("color: #d0d0d0; font-size: 11px; font-weight: 500; letter-spacing: 2px;")
        left_layout.addWidget(dev_label)

        self.ta_device_list = QTableWidget()
        self.ta_device_list.setColumnCount(2)
        self.ta_device_list.setHorizontalHeaderLabels([self.i18n.t("ip"), self.i18n.t("packets")])
        self.ta_device_list.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.ta_device_list.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.ta_device_list.setColumnWidth(1, 75)
        self.ta_device_list.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_device_list.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_device_list.verticalHeader().setVisible(False)
        self.ta_device_list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_device_list.itemClicked.connect(self._ta_filter_by_device)
        left_layout.addWidget(self.ta_device_list, stretch=1)

        # Кнопка сброса фильтра устройств.
        btn_clear_filter = QPushButton("ПОКАЗАТЬ ВСЕ")
        btn_clear_filter.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        btn_clear_filter.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #555;
                border: 1px solid #222;
                padding: 3px;
                font-size: 9px;
                border-radius: 8px;
            }
        """)
        btn_clear_filter.clicked.connect(lambda: self._ta_apply_filter(""))
        left_layout.addWidget(btn_clear_filter)

        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setSpacing(0)
        right_layout.setContentsMargins(0, 0, 0, 0)

        header = QWidget()
        header.setFixedHeight(36)
        header.setStyleSheet("background-color: #252526; border-bottom: 1px solid #3c3c3c;")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 0, 12, 0)

        header_label = QLabel("// анализ трафика")
        header_label.setStyleSheet("color: #d0d0d0; font-size: 11px;")
        header_layout.addWidget(header_label)
        header_layout.addStretch()

        # Кнопка запуска захвата трафика.
        self.btn_start_capture = QPushButton(self.i18n.t("start"))
        self.btn_start_capture.setFixedWidth(80)
        self.btn_start_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_start_capture.clicked.connect(self._ta_start)
        # Размер как был, цвет — как у общего стиля кнопок.
        self.btn_start_capture.setStyleSheet("""
            QPushButton {
                background-color: #2d2d2d;
                color: #ffffff;
                border: 1px solid #8a8a8a;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 700;
                border-radius: 8px;
            }
            QPushButton:disabled { color: #bdbdbd; background-color: #2a2a2a; border-color: #3f3f3f; }
        """)
        header_layout.addWidget(self.btn_start_capture)
        header_layout.addSpacing(6)

        # Кнопка остановки захвата трафика.
        self.btn_stop_capture = QPushButton(self.i18n.t("stop"))
        self.btn_stop_capture.setFixedWidth(80)
        self.btn_stop_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_stop_capture.setEnabled(False)
        self.btn_stop_capture.clicked.connect(self._ta_stop)
        self.btn_stop_capture.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ff4444;
                border: 1px solid #ff444444;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
            QPushButton:disabled { color: #c0c0c0; border-color: #222; }
        """)
        header_layout.addWidget(self.btn_stop_capture)
        header_layout.addSpacing(6)

        # Кнопка очистки таблицы трафика.
        self.btn_clear_capture = QPushButton(self.i18n.t("clear"))
        self.btn_clear_capture.setFixedWidth(80)
        self.btn_clear_capture.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_clear_capture.clicked.connect(self._ta_clear)
        self.btn_clear_capture.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #666666;
                border: 1px solid #c0c0c0;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
        """)
        header_layout.addWidget(self.btn_clear_capture)
        header_layout.addSpacing(6)

        # Кнопка экспорта трафика в CSV.
        self.btn_ta_export = QPushButton(self.i18n.t("export_csv"))
        self.btn_ta_export.setFixedWidth(120)
        self.btn_ta_export.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_ta_export.setEnabled(False)
        self.btn_ta_export.clicked.connect(self._export_ta_csv)
        self.btn_ta_export.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: 1px solid #909090;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
            QPushButton:disabled { color: #c0c0c0; border-color: #222; }
        """)
        header_layout.addWidget(self.btn_ta_export)
        header_layout.addSpacing(6)

        # Кнопка сохранения захваченных пакетов в PCAP.
        self.btn_ta_pcap = QPushButton(self.i18n.t("pcap"))
        self.btn_ta_pcap.setFixedWidth(80)
        self.btn_ta_pcap.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.btn_ta_pcap.setToolTip("Выбрать файл PCAP для записи захвата")
        self.btn_ta_pcap.clicked.connect(self._ta_select_pcap)
        self.btn_ta_pcap.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: 1px solid #909090;
                padding: 4px 10px;
                font-size: 10px;
                font-weight: 500;
                border-radius: 8px;
            }
        """)
        header_layout.addWidget(self.btn_ta_pcap)
        right_layout.addWidget(header)

        filter_bar = QWidget()
        filter_bar.setFixedHeight(28)
        filter_bar.setStyleSheet("background-color: #262626; border-bottom: 1px solid #111;")
        filter_layout = QHBoxLayout(filter_bar)
        filter_layout.setContentsMargins(12, 0, 12, 0)

        filter_label = QLabel("ФИЛЬТР:")
        filter_label.setStyleSheet("color: #444; font-size: 10px;")
        filter_layout.addWidget(filter_label)
        filter_layout.addSpacing(8)

        self.ta_filter = QLineEdit()
        self.ta_filter.setPlaceholderText(self.i18n.t("ph_traffic_filter"))
        self.ta_filter.setStyleSheet("""
            QLineEdit {
                background-color: #1e1e1e;
                color: #aaaaaa;
                border: 1px solid #3c3c3c;
                padding: 2px 8px;
                font-size: 11px;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                border-radius: 8px;
            }
            QLineEdit:focus { border-color: #ffffff; }
        """)
        self.ta_filter.textChanged.connect(self._ta_apply_filter)
        filter_layout.addWidget(self.ta_filter, stretch=2)
        filter_layout.addSpacing(8)
        bpf_label = QLabel("BPF:")
        bpf_label.setStyleSheet("color: #444; font-size: 10px;")
        filter_layout.addWidget(bpf_label)
        self.ta_bpf = QLineEdit()
        self.ta_bpf.setPlaceholderText("ip, tcp port 443, udp ...")
        self.ta_bpf.setStyleSheet(self.ta_filter.styleSheet())
        filter_layout.addWidget(self.ta_bpf, stretch=1)
        right_layout.addWidget(filter_bar)

        self.ta_table = QTableWidget()
        self.ta_table.setColumnCount(7)
        self.ta_table.setHorizontalHeaderLabels([
            "#", self.i18n.t("col_time_short"), self.i18n.t("col_src"), self.i18n.t("col_dst"), self.i18n.t("col_proto"), self.i18n.t("col_port_short"), self.i18n.t("col_size")
        ])
        self.ta_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.ta_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col, w in [(0, 55), (1, 90), (4, 105), (5, 75), (6, 90)]:
            self.ta_table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeMode.Fixed)
            self.ta_table.setColumnWidth(col, w)
        self.ta_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.ta_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.ta_table.verticalHeader().setVisible(False)
        self.ta_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.ta_table.itemDoubleClicked.connect(self._ta_send_to_scan)
        self.ta_table.setAlternatingRowColors(True)
        self.ta_table.setStyleSheet("""
            QTableWidget { alternate-background-color: #0f0f0f; }
        """)
        right_layout.addWidget(self.ta_table, stretch=1)

        self.ta_status = QLabel("// готово - нажмите СТАРТ для захвата")
        self.ta_status.setStyleSheet("""
            background-color: #252526;
            color: #c0c0c0;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)
        right_layout.addWidget(self.ta_status)
        layout.addWidget(right, stretch=1)

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}

        return page

    def _ta_start(self):
        iface = self.iface_selector.currentData()
        if not iface:
            return

        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_proto_stats = {}
        self._ta_port_stats = {}
        self._ta_src_stats = {}
        self._ta_flows = set()
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)

        self.btn_start_capture.setEnabled(False)
        self.btn_stop_capture.setEnabled(True)
        self.ta_status.setText(f"// capturing on {iface['name']}...")
        self.ta_status.setStyleSheet("""
            background-color: #252526;
            color: #00ccff;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)

        bpf = self.ta_bpf.text().strip() if hasattr(self, "ta_bpf") else "ip"
        pcap_path = getattr(self, "_ta_pcap_path", None)
        self.ta_worker = TrafficWorker(iface["name"], bpf=bpf or "ip", pcap_path=pcap_path)
        self.ta_worker.packet_captured.connect(self._ta_on_packet)
        self.ta_worker.finished.connect(self._ta_on_finished)
        if hasattr(self.ta_worker, "error"):
            self.ta_worker.error.connect(self._ta_on_error)
        self.ta_worker.start()

    def _ta_stop(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)
        self.ta_status.setStyleSheet("""
            background-color: #252526;
            color: #c0c0c0;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)

    def _ta_clear(self):
        if hasattr(self, 'ta_worker') and self.ta_worker.isRunning():
            self.ta_worker.stop()
            self.btn_start_capture.setEnabled(True)
            self.btn_stop_capture.setEnabled(False)
        self._ta_packets = []
        self._ta_packet_count = 0
        self._ta_start_time = None
        self._ta_device_stats = {}
        self._ta_proto_stats = {}
        self._ta_port_stats = {}
        self._ta_src_stats = {}
        self._ta_flows = set()
        self._ta_data = []
        self.ta_table.setRowCount(0)
        self.ta_device_list.setRowCount(0)
        self.btn_ta_export.setEnabled(False)
        self.ta_status.setText("// очищено — нажмите СТАРТ для захвата")

    def _ta_select_pcap(self):
        # Выбор PCAP-файла для записи захвата.
        path, _ = QFileDialog.getSaveFileName(self, "PCAP файл", f"capture-{time.strftime('%Y%m%d-%H%M%S')}.pcap", "PCAP (*.pcap);;All files (*)")
        if not path:
            return
        self._ta_pcap_path = path
        self.ta_status.setText(f"// PCAP: {path}")

    def _ta_on_error(self, msg: str):
        # Ошибка захвата/PCAP/BPF.
        self.ta_status.setText(f"// error: {msg}")
        self.ta_status.setStyleSheet("""
            background-color: #252526;
            color: #ff4444;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)

    def _ta_on_packet(self, pkt: dict):
        if not hasattr(self, '_ta_packets'):
            return

        if self._ta_start_time is None:
            self._ta_start_time = time.time()

        elapsed = time.time() - self._ta_start_time
        self._ta_packet_count += 1

        src_label = self._resolve_ip_label(pkt["src"])
        dst_label = self._resolve_ip_label(pkt["dst"])

        packet_data = {
            "n": self._ta_packet_count,
            "time": f"{elapsed:.3f}s",
            "src": pkt["src"],
            "dst": pkt["dst"],
            "src_label": src_label,
            "dst_label": dst_label,
            "proto": pkt["proto"],
            "port": pkt["port"],
            "size": pkt["size"],
        }

        self._ta_packets.append(packet_data)

        for ip in [pkt["src"], pkt["dst"]]:
            self._ta_device_stats[ip] = self._ta_device_stats.get(ip, 0) + 1
        src_ip = pkt.get("src", "")
        if src_ip:
            self._ta_src_stats[src_ip] = self._ta_src_stats.get(src_ip, 0) + 1
        proto = pkt.get("proto", "OTHER")
        port = str(pkt.get("port", "-"))
        flow_key = (pkt.get("src",""), pkt.get("dst",""), proto, port)
        self._ta_flows.add(flow_key)
        self._ta_proto_stats[proto] = self._ta_proto_stats.get(proto, 0) + 1
        if port != "-":
            self._ta_port_stats[port] = self._ta_port_stats.get(port, 0) + 1

        self._ta_add_row(packet_data)

        if self._ta_packet_count % 20 == 0 or self._ta_packet_count <= 5:
            self._ta_update_device_list()
            top_proto = max(self._ta_proto_stats, key=self._ta_proto_stats.get) if self._ta_proto_stats else "-"
            top_port = max(self._ta_port_stats, key=self._ta_port_stats.get) if self._ta_port_stats else "-"
            top_talker = max(self._ta_src_stats, key=self._ta_src_stats.get) if self._ta_src_stats else "-"
            talker_share = (self._ta_src_stats.get(top_talker, 0) / self._ta_packet_count * 100) if self._ta_packet_count else 0
            flows = len(getattr(self, "_ta_flows", set()))
            warn = " | АНОМАЛИЯ: доминирует источник" if talker_share > 45 and self._ta_packet_count > 80 else ""
            self.ta_status.setText(
                f"// {self._ta_packet_count} packets — {elapsed:.1f}s | proto: {top_proto} | port: {top_port} | top src: {top_talker} ({talker_share:.0f}%) | flows: {flows}{warn}"
            )
            if self._ta_packet_count > 0:
                self.btn_ta_export.setEnabled(True)

    def _resolve_ip_label(self, ip: str) -> str:
        if hasattr(self, 'last_hosts'):
            for h in self.last_hosts:
                if h["ip"] == ip:
                    hostname = h.get("hostname", ip)
                    if hostname != ip:
                        return f"{ip} ({hostname.split('.')[0]})"
        return ip

    def _ta_add_row(self, pkt: dict):
        proto_colors = {
            "TCP":  "#333333",
            "UDP":  "#1a2e1a",
            "ICMP": "#2e1a1a",
            "OTHER": "#2b2b2b",
        }
        bg = QColor(proto_colors.get(pkt["proto"], "#2b2b2b"))

        row = self.ta_table.rowCount()
        self.ta_table.insertRow(row)

        items = [
            str(pkt["n"]),
            pkt["time"],
            pkt["src_label"],
            pkt["dst_label"],
            pkt["proto"],
            pkt["port"],
            f"{pkt['size']}B",
            pkt.get("info", ""),
        ]

        for col, text in enumerate(items):
            item = QTableWidgetItem(text)
            item.setBackground(bg)
            if col == 4:
                colors = {"TCP": "#4488ff", "UDP": "#44cc88", "ICMP": "#ff8844", "OTHER": "#888888"}
                item.setForeground(QColor(colors.get(pkt["proto"], "#888888")))
            self.ta_table.setItem(row, col, item)

        self.ta_table.scrollToBottom()

    def _ta_update_device_list(self):
        self.ta_device_list.setRowCount(0)
        sorted_devs = sorted(self._ta_device_stats.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_devs:
            row = self.ta_device_list.rowCount()
            self.ta_device_list.insertRow(row)
            label = self._resolve_ip_label(ip)
            self.ta_device_list.setItem(row, 0, QTableWidgetItem(label))
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.ta_device_list.setItem(row, 1, count_item)

    def _ta_filter_by_device(self, item):
        row = item.row()
        ip_cell = self.ta_device_list.item(row, 0)
        if ip_cell:
            label = ip_cell.text()
            ip = label.split(" ")[0]
            self.ta_filter.setText(ip)

    def _ta_apply_filter(self, text):
        text = text.lower()
        for row in range(self.ta_table.rowCount()):
            visible = not text or any(
                text in (self.ta_table.item(row, col).text().lower() if self.ta_table.item(row, col) else "")
                for col in range(self.ta_table.columnCount())
            )
            self.ta_table.setRowHidden(row, not visible)
        visible_count = sum(
            1 for r in range(self.ta_table.rowCount())
            if not self.ta_table.isRowHidden(r)
        )
        if hasattr(self, '_ta_packet_count'):
            self.ta_status.setText(
                f"// showing {visible_count} of {self._ta_packet_count} packets"
                if text else
                f"// {self._ta_packet_count} packets captured"
            )

    def _ta_on_finished(self):
        self.btn_start_capture.setEnabled(True)
        self.btn_stop_capture.setEnabled(False)

    def _build_diagnostics_page(self):
        # Вкладка диагностики сети: адаптер, Wi-Fi, DHCP/DNS, шлюз, интернет, MTU.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.diag_title_label = QLabel(self.i18n.t("diag_title"))
        self.diag_title_label.setObjectName("title_label")
        header.addWidget(self.diag_title_label)
        header.addStretch()
        self.btn_diag_refresh = QPushButton(self.i18n.t("check"))
        self.btn_diag_refresh.setToolTip("Собрать информацию о сети и проверить доступность")
        self.btn_diag_refresh.clicked.connect(self._run_diagnostics_page)
        self.btn_diag_clear = QPushButton(self.i18n.t("clear"))
        self.btn_diag_clear.setToolTip("Очистить вывод диагностики")
        self.btn_diag_clear.clicked.connect(self._clear_diagnostics_page)
        header.addWidget(self.btn_diag_refresh)
        header.addWidget(self.btn_diag_clear)
        layout.addLayout(header)

        hint = QLabel(self.i18n.t("diag_desc"))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #aaaaaa; font-size: 11px;")
        layout.addWidget(hint)

        self.diag_output = QTextEdit()
        self.diag_output.setReadOnly(True)
        self.diag_output.setStyleSheet("font-family: Consolas, 'Courier New', monospace; font-size: 12px;")
        self.diag_output.setPlainText("Нажмите «ПРОВЕРИТЬ», чтобы собрать диагностику.")
        layout.addWidget(self.diag_output, stretch=1)
        return page

    def _clear_diagnostics_page(self):
        # Очистка вывода диагностики сети.
        self.diag_output.setPlainText("Нажмите «ПРОВЕРИТЬ», чтобы собрать диагностику.")
        self.statusBar().showMessage("Диагностика очищена.")

    def _run_diagnostics_page(self):
        # Запуск сбора диагностики в фоне.
        if hasattr(self, "diag_worker") and self.diag_worker.isRunning():
            return
        self.btn_diag_refresh.setEnabled(False)
        self.diag_output.setPlainText("Сбор диагностики...")
        self.diag_worker = DiagnosticsWorker()
        self.diag_worker.finished.connect(self._on_diagnostics_page_finished)
        self.diag_worker.start()

    def _on_diagnostics_page_finished(self, data):
        self.btn_diag_refresh.setEnabled(True)
        lines = []
        adapter = data.get("adapter", {})
        wifi = data.get("wifi", {})
        checks = data.get("checks", {})
        if data.get("error"):
            lines.append(f"Ошибка: {data['error']}")
        lines.append("== Адаптер ==")
        lines.append(f"Имя: {adapter.get('name', '—')}")
        lines.append(f"IP: {adapter.get('ip', '—')}")
        lines.append(f"Маска: {adapter.get('mask', '—')}")
        lines.append(f"Шлюз: {adapter.get('gateway', checks.get('gateway','—')) or '—'}")
        dns = adapter.get("dns") or []
        lines.append(f"DNS: {', '.join(dns) if dns else '—'}")
        dhcp = adapter.get("dhcp")
        dhcp_txt = "—" if dhcp is None else ("включён" if dhcp else "выключен")
        lines.append(f"DHCP: {dhcp_txt}")
        lines.append(f"MTU: {adapter.get('mtu', '—')}")
        lines.append(f"Скорость: {adapter.get('speed_mbps', '—')} Mbps")
        lines.append("")
        lines.append("== Wi-Fi ==")
        if wifi:
            lines.append(f"Состояние: {wifi.get('state', '—')}")
            lines.append(f"SSID: {wifi.get('ssid', '—')}")
            lines.append(f"BSSID: {wifi.get('bssid', '—')}")
            lines.append(f"Сигнал: {wifi.get('signal', '—')}")
            lines.append(f"Канал: {wifi.get('channel', '—')}")
            lines.append(f"Радио: {wifi.get('radio', '—')}")
            lines.append(f"Аутентификация: {wifi.get('auth', '—')}")
            lines.append(f"Шифр: {wifi.get('cipher', '—')}")
            open_net = wifi.get("open_network")
            if open_net is True:
                lines.append("Тип: открытая сеть (без защиты)")
            elif open_net is False:
                lines.append("Тип: защищённая сеть")
            if wifi.get("rx") or wifi.get("tx"):
                lines.append(f"Скорость RX/TX: {wifi.get('rx','—')} / {wifi.get('tx','—')} Mbps")
        else:
            lines.append("Wi-Fi не обнаружен или адаптер не беспроводной.")
        lines.append("")
        lines.append("== Проверки доступности ==")
        lines.append(f"Шлюз ({checks.get('gateway','—')}): {'OK' if checks.get('gateway_ok') else 'НЕТ ОТВЕТА'}")
        lines.append(f"DNS: {'OK' if checks.get('dns_ok') else 'НЕТ'}")
        lines.append(f"Интернет (TCP 443): {'OK' if checks.get('internet_ok') else 'НЕТ'}")
        if not checks.get("gateway_ok"):
            lines.append("Подсказка: нет ответа от шлюза — проверь кабель/Wi-Fi/роутер.")
        if checks.get("gateway_ok") and not checks.get("dns_ok"):
            lines.append("Подсказка: шлюз доступен, но DNS не отвечает — проблема в DNS/интернете.")
        if checks.get("dns_ok") and not checks.get("internet_ok"):
            lines.append("Подсказка: DNS работает, но интернет недоступен — возможна фильтрация/проблема провайдера.")
        self.diag_output.setPlainText("\n".join(lines))

    def _build_inventory_page(self):
        # Вкладка журнала и инвентаря устройств.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.inv_title_label = QLabel(self.i18n.t("inv_title"))
        self.inv_title_label.setObjectName("title_label")
        header.addWidget(self.inv_title_label)
        header.addStretch()
        self.btn_inv_refresh = QPushButton(self.i18n.t("refresh"))
        self.btn_inv_refresh.setToolTip("Обновить список известных устройств из истории")
        self.btn_inv_refresh.clicked.connect(self._refresh_inventory_page)
        header.addWidget(self.btn_inv_refresh)
        layout.addLayout(header)

        self.inv_hint_label = QLabel(self.i18n.t("inv_hint"))
        self.inv_hint_label.setWordWrap(True)
        self.inv_hint_label.setStyleSheet("color: #aaaaaa; font-size: 11px;")
        layout.addWidget(self.inv_hint_label)

        self.inventory_table = QTableWidget(0, 7)
        self.inventory_table.setHorizontalHeaderLabels([self.i18n.t("col_ip"), self.i18n.t("col_mac"), self.i18n.t("col_name"), self.i18n.t("col_first_seen"), self.i18n.t("col_last_seen"), self.i18n.t("col_tag"), self.i18n.t("col_note")])
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.inventory_table.horizontalHeader().setStretchLastSection(True)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.inventory_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inventory_table.verticalHeader().setVisible(False)
        layout.addWidget(self.inventory_table, stretch=1)

        actions = QHBoxLayout()
        self.btn_inv_tag = QPushButton("МЕТКА")
        self.btn_inv_tag.setToolTip("Задать метку для выбранного устройства")
        self.btn_inv_tag.clicked.connect(self._inventory_set_tag)
        self.btn_inv_note = QPushButton("ЗАМЕТКА")
        self.btn_inv_note.setToolTip("Задать заметку для выбранного устройства")
        self.btn_inv_note.clicked.connect(self._inventory_set_note)
        self.btn_inv_clear = QPushButton(self.i18n.t("clear"))
        self.btn_inv_clear.setToolTip("Очистить журнал и инвентарь устройств")
        self.btn_inv_clear.clicked.connect(self._clear_inventory)
        # Компактный стиль для кнопок действий инвентаря.
        for b in [self.btn_inv_tag, self.btn_inv_note, self.btn_inv_clear]:
            b.setStyleSheet("QPushButton { padding: 4px 8px; font-size: 11px; border-radius: 6px; }")
        actions.addWidget(self.btn_inv_tag)
        actions.addWidget(self.btn_inv_note)
        actions.addWidget(self.btn_inv_clear)
        actions.addStretch()
        layout.addLayout(actions)
        return page

    def _inventory_path(self):
        return os.path.join(self._history_dir(), "inventory.json")

    def _load_inventory(self):
        path = self._inventory_path()
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            logging.getLogger(__name__).debug("Failed to load inventory file", exc_info=True)
            return {}

    def _save_inventory(self, inv):
        os.makedirs(self._history_dir(), exist_ok=True)
        with open(self._inventory_path(), "w", encoding="utf-8") as f:
            json.dump(inv, f, ensure_ascii=False, indent=2)

    def _update_inventory_from_hosts(self, hosts):
        # Обновление инвентаря по результатам сканирования.
        inv = self._load_inventory()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for h in hosts or []:
            mac = (h.get("mac") or "").lower()
            ip = h.get("ip") or ""
            key = mac or ip
            if not key:
                continue
            item = inv.get(key, {})
            item.setdefault("first_seen", now)
            item["last_seen"] = now
            item["ip"] = ip
            item["mac"] = h.get("mac", "")
            item["hostname"] = h.get("hostname", "")
            item.setdefault("tag", "")
            item.setdefault("note", "")
            inv[key] = item
        self._save_inventory(inv)

    def _refresh_inventory_page(self):
        inv = self._load_inventory()
        rows = list(inv.values())
        rows.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
        self.inventory_table.setRowCount(0)
        for item in rows:
            row = self.inventory_table.rowCount()
            self.inventory_table.insertRow(row)
            vals = [item.get("ip",""), item.get("mac",""), item.get("hostname",""), item.get("first_seen",""), item.get("last_seen",""), item.get("tag",""), item.get("note","")]
            for c, v in enumerate(vals):
                self.inventory_table.setItem(row, c, QTableWidgetItem(str(v)))

    def _inventory_selected_key(self):
        row = self.inventory_table.currentRow()
        if row < 0:
            return None
        mac = self.inventory_table.item(row, 1).text().strip().lower() if self.inventory_table.item(row, 1) else ""
        ip = self.inventory_table.item(row, 0).text().strip() if self.inventory_table.item(row, 0) else ""
        return mac or ip

    def _inventory_set_tag(self):
        key = self._inventory_selected_key()
        if not key:
            return
        inv = self._load_inventory()
        item = inv.get(key, {})
        text, ok = QInputDialog.getText(self, "Метка", "Метка устройства:", text=item.get("tag",""))
        if not ok:
            return
        item["tag"] = text.strip()
        inv[key] = item
        self._save_inventory(inv)
        self._refresh_inventory_page()

    def _clear_inventory(self):
        # Очистка журнала и инвентаря устройств.
        confirm = QMessageBox.question(
            self,
            "Очистить инвентарь",
            "Удалить журнал и инвентарь устройств? Это действие нельзя отменить.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        path = self._inventory_path()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            logging.getLogger(__name__).debug("Failed to clear inventory file", exc_info=True)
        self._refresh_inventory_page()
        self.statusBar().showMessage("Журнал и инвентарь очищены.")

    def _inventory_set_note(self):
        key = self._inventory_selected_key()
        if not key:
            return
        inv = self._load_inventory()
        item = inv.get(key, {})
        text, ok = QInputDialog.getMultiLineText(self, "Заметка", "Заметка устройства:", item.get("note",""))
        if not ok:
            return
        item["note"] = text.strip()
        inv[key] = item
        self._save_inventory(inv)
        self._refresh_inventory_page()

    def _availability_log_path(self):
        return os.path.join(self._history_dir(), "availability.jsonl")

    def _append_availability_record(self, kind, target, ok, detail=""):
        # Запись результата проверки доступности в журнал.
        try:
            os.makedirs(self._history_dir(), exist_ok=True)
            rec = {
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "kind": kind,
                "target": target,
                "ok": bool(ok),
                "detail": detail,
            }
            with open(self._availability_log_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            logging.getLogger(__name__).debug("Failed to append availability record", exc_info=True)

    def _load_availability_records(self, limit=200):
        path = self._availability_log_path()
        if not os.path.exists(path):
            return []
        rows = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except Exception:
                        logging.getLogger(__name__).debug("Failed to parse availability line", exc_info=True)
        except Exception:
            logging.getLogger(__name__).debug("Failed to read availability log", exc_info=True)
            return []
        return rows[-limit:]

    def _build_monitoring_page(self):
        # Вкладка мониторинга доступности шлюза и критичных узлов.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.mon_title_label = QLabel(self.i18n.t("mon_title"))
        self.mon_title_label.setObjectName("title_label")
        header.addWidget(self.mon_title_label)
        header.addStretch()
        self.btn_mon_refresh = QPushButton(self.i18n.t("refresh"))
        self.btn_mon_refresh.clicked.connect(self._refresh_monitoring_page)
        self.btn_mon_export = QPushButton(self.i18n.t("export"))
        self.btn_mon_export.setToolTip("Экспортировать журнал мониторинга доступности")
        self.btn_mon_export.clicked.connect(self._export_monitoring_report)
        self.btn_mon_clear = QPushButton(self.i18n.t("clear"))
        self.btn_mon_clear.setToolTip("Очистить журнал мониторинга доступности")
        self.btn_mon_clear.clicked.connect(self._clear_monitoring_page)
        header.addWidget(self.btn_mon_refresh)
        header.addWidget(self.btn_mon_export)
        header.addWidget(self.btn_mon_clear)
        layout.addLayout(header)

        hint = QLabel(self.i18n.t("mon_desc"))
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #aaaaaa; font-size: 11px;")
        layout.addWidget(hint)

        self.mon_summary = QLabel("Нет данных")
        self.mon_summary.setWordWrap(True)
        layout.addWidget(self.mon_summary)

        self.mon_table = QTableWidget(0, 4)
        self.mon_table.setHorizontalHeaderLabels([self.i18n.t("col_time"), self.i18n.t("col_type"), self.i18n.t("col_target"), self.i18n.t("col_status_details")])
        self.mon_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.mon_table.horizontalHeader().setStretchLastSection(True)
        self.mon_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.mon_table.verticalHeader().setVisible(False)
        layout.addWidget(self.mon_table, stretch=1)
        return page

    def _clear_monitoring_page(self):
        # Очистка журнала мониторинга доступности.
        confirm = QMessageBox.question(
            self,
            "Очистить мониторинг",
            "Удалить журнал мониторинга доступности? Это действие нельзя отменить.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        path = self._availability_log_path()
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            logging.getLogger(__name__).debug("Failed to clear availability log", exc_info=True)
        self.mon_table.setRowCount(0)
        self.mon_summary.setText("Нет данных")
        self.statusBar().showMessage("Мониторинг доступности очищен.")

    def _export_monitoring_report(self):
        # Экспорт журнала мониторинга доступности.
        rows = self._load_availability_records(limit=1000)
        if not rows:
            QMessageBox.information(self, "Экспорт мониторинга", "Нет данных для экспорта.")
            return
        default_name = f"monitoring-{time.strftime('%Y%m%d-%H%M%S')}.csv"
        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Экспорт мониторинга", default_name, "CSV (*.csv);;Text (*.txt);;All files (*)"
        )
        if not path:
            return
        try:
            if path.lower().endswith(".txt"):
                lines = ["Время\tТип\tЦель\tСтатус\tДетали"]
                for rec in rows:
                    status = "OK" if rec.get("ok") else "НЕДОСТУПЕН"
                    lines.append(f"{rec.get('ts','')}\t{rec.get('kind','')}\t{rec.get('target','')}\t{status}\t{rec.get('detail','')}")
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
            else:
                import csv
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["ts", "kind", "target", "ok", "detail"])
                    for rec in rows:
                        w.writerow([rec.get("ts",""), rec.get("kind",""), rec.get("target",""), rec.get("ok"), rec.get("detail","")])
            self.statusBar().showMessage(f"Мониторинг экспортирован: {path}")
        except Exception as e:
            QMessageBox.warning(self, "Экспорт мониторинга", f"Не удалось сохранить файл: {e}")

    def _refresh_monitoring_page(self):
        rows = self._load_availability_records(limit=300)
        self.mon_table.setRowCount(0)
        ok_count = 0
        last_fail = {}
        per_target = {}
        for rec in rows:
            target = rec.get("target", "")
            per_target.setdefault(target, {"ok": 0, "fail": 0})
            if rec.get("ok"):
                ok_count += 1
                per_target[target]["ok"] += 1
            else:
                per_target[target]["fail"] += 1
                last_fail[target] = rec.get("ts", "")

        for rec in reversed(rows):
            row = self.mon_table.rowCount()
            self.mon_table.insertRow(row)
            status = "OK" if rec.get("ok") else "НЕДОСТУПЕН"
            detail = rec.get("detail") or ""
            text = status if not detail else f"{status} — {detail}"
            vals = [rec.get("ts", ""), rec.get("kind", ""), rec.get("target", ""), text]
            for c, v in enumerate(vals):
                self.mon_table.setItem(row, c, QTableWidgetItem(str(v)))

        total = len(rows)
        gw = getattr(self, "_gateway_status", None)
        gw_txt = "неизвестно" if gw is None else ("доступен" if gw else "недоступен")
        parts = [f"Записей: {total}", f"OK: {ok_count}", f"Проблем: {total - ok_count}", f"Шлюз сейчас: {gw_txt}"]
        if last_fail:
            worst = sorted(per_target.items(), key=lambda kv: kv[1]["fail"], reverse=True)[:3]
            worst_txt = "; ".join([f"{t} (сбоев {s['fail']}, посл. {last_fail.get(t,'—')})" for t, s in worst if s["fail"] > 0])
            if worst_txt:
                parts.append(f"Проблемные: {worst_txt}")
        self.mon_summary.setText(" | ".join(parts))

    def _build_audit_page(self):
        # Вкладка аудита безопасности по последнему сканированию.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        header = QHBoxLayout()
        self.audit_title_label = QLabel(self.i18n.t("audit_title"))
        self.audit_title_label.setObjectName("title_label")
        header.addWidget(self.audit_title_label)
        header.addStretch()
        self.btn_audit_refresh = QPushButton(self.i18n.t("refresh"))
        self.btn_audit_refresh.clicked.connect(self._refresh_audit_page)
        self.btn_audit_export = QPushButton(self.i18n.t("export"))
        self.btn_audit_export.setToolTip("Экспортировать сводку аудита в текстовый файл")
        self.btn_audit_export.clicked.connect(self._export_audit_report)
        self.btn_audit_clear = QPushButton(self.i18n.t("clear"))
        self.btn_audit_clear.setToolTip("Очистить вывод аудита безопасности")
        self.btn_audit_clear.clicked.connect(self._clear_audit_page)
        header.addWidget(self.btn_audit_refresh)
        header.addWidget(self.btn_audit_export)
        header.addWidget(self.btn_audit_clear)
        layout.addLayout(header)

        hint = QLabel("Сводка по признакам: рискованные порты, filtered-порты, камеры/IoT, embedded-устройства. CVE/тип — по признакам, не 100% подтверждение.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #aaaaaa; font-size: 11px;")
        layout.addWidget(hint)

        self.audit_output = QTextEdit()
        self.audit_output.setReadOnly(True)
        self.audit_output.setStyleSheet("font-family: Consolas, 'Courier New', monospace; font-size: 12px;")
        layout.addWidget(self.audit_output, stretch=1)
        return page

    def _refresh_audit_page(self):
        hosts = getattr(self, "last_hosts", []) or []
        lines = []
        lines.append(f"Устройств в последнем сканировании: {len(hosts)}")
        if not hosts:
            lines.append("Нет данных. Выполните сканирование сети.")
            self.audit_output.setPlainText("\n".join(lines))
            return
        risky_ports = {21:"FTP",23:"Telnet",445:"SMB",3389:"RDP",5900:"VNC",135:"RPC",139:"NetBIOS"}
        total_open = 0
        total_filtered = 0
        risky_hosts = []
        cameras = []
        embedded = []
        for h in hosts:
            open_ports = h.get("open_ports", []) or []
            filtered = h.get("filtered_ports", []) or []
            total_open += len(open_ports)
            total_filtered += len(filtered)
            found = [f"{p}/{risky_ports[p]}" for p in open_ports if p in risky_ports]
            if found or filtered:
                risky_hosts.append(f"{h.get('ip','')} {h.get('hostname','')} | open: {', '.join(found) or '—'} | filtered: {', '.join(map(str, filtered)) or '—'}")
            if h.get("camera_hint"):
                cameras.append(f"{h.get('ip','')} {h.get('hostname','')} | {h.get('camera_hint')}")
            if h.get("embedded_device"):
                embedded.append(f"{h.get('ip','')} {h.get('hostname','')} | {h.get('embedded_device')}")
        lines.append(f"Открытых портов (сумма): {total_open}")
        lines.append(f"Filtered-портов (сумма, признак): {total_filtered}")
        lines.append("")
        lines.append(f"Узлы с рисковыми/filtered портами: {len(risky_hosts)}")
        lines.extend(risky_hosts[:50] or ["—"])
        lines.append("")
        lines.append(f"Возможные камеры/видеоустройства (по признакам): {len(cameras)}")
        lines.extend(cameras[:50] or ["—"])
        lines.append("")
        lines.append(f"Embedded/IoT признаки: {len(embedded)}")
        lines.extend(embedded[:50] or ["—"])
        lines.append("")
        lines.append("Примечание: результаты эвристические. CVE и тип устройства требуют подтверждения.")
        self.audit_output.setPlainText("\n".join(lines))

    def _export_audit_report(self):
        # Экспорт сводки аудита безопасности в файл.
        text = self.audit_output.toPlainText().strip()
        if not text:
            QMessageBox.information(self, "Экспорт аудита", "Нет данных для экспорта.")
            return
        default_name = f"audit-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт аудита", default_name, "Text (*.txt);;CSV (*.csv);;All files (*)"
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                import csv
                hosts = getattr(self, "last_hosts", []) or []
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["ip", "hostname", "vendor", "open_ports", "filtered_ports", "camera_hint", "embedded_device", "http_title", "tls_cert", "smb_info"])
                    for h in hosts:
                        w.writerow([
                            h.get("ip", ""), h.get("hostname", ""), h.get("vendor", ""),
                            " ".join(map(str, h.get("open_ports", []) or [])),
                            " ".join(map(str, h.get("filtered_ports", []) or [])),
                            h.get("camera_hint", ""), h.get("embedded_device", ""),
                            h.get("http_title", ""), h.get("tls_cert", ""), h.get("smb_info", ""),
                        ])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            self.statusBar().showMessage(f"Аудит экспортирован: {path}")
        except Exception as e:
            QMessageBox.warning(self, "Экспорт аудита", f"Не удалось сохранить файл: {e}")

    def _clear_audit_page(self):
        # Очистка вывода аудита безопасности.
        self.audit_output.setPlainText("Нет данных. Выполните сканирование сети или нажмите «ОБНОВИТЬ».")
        self.statusBar().showMessage("Аудит безопасности очищен.")

    def _build_table(self):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Фильтр устройств в таблице.
        self.table_filter = QLineEdit()
        self.table_filter.setPlaceholderText(self.i18n.t("ph_table_filter"))
        self.table_filter.textChanged.connect(self._filter_table)
        layout.addWidget(self.table_filter)

        self.table = QTableWidget()
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([self.i18n.t("col_ip"), self.i18n.t("col_mac"), self.i18n.t("col_vendor"), self.i18n.t("col_hostname")])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self._on_device_selected)
        self.table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        layout.addWidget(self.table)
        return container

    def _filter_table(self, text):
        # Фильтрация строк таблицы устройств по подстроке.
        needle = (text or "").strip().lower()
        for row in range(self.table.rowCount()):
            match = not needle
            if needle:
                for col in range(self.table.columnCount()):
                    item = self.table.item(row, col)
                    if item and needle in item.text().lower():
                        match = True
                        break
            self.table.setRowHidden(row, not match)

    def _show_menu(self, pos):
        item = self.table.itemAt(pos)

        if item is None:
            return

        row = item.row()
        ip = self.table.item(row,0).text()

        menu = QMenu()

        # Действия контекстного меню для выбранного хоста.
        portScan_action = QAction("Отправить в сканирование портов", self)
        ta_action = QAction("Отправить в анализ трафика", self)
        as_action = QAction("Отправить в поверхность атаки", self)

        portScan_action.triggered.connect(lambda: (self.stack.setCurrentIndex(1), self.scan_target.setText(ip), self._set_active_nav(1)))
        ta_action.triggered.connect(lambda: (self.stack.setCurrentIndex(4), self.ta_filter.setText(ip), self._set_active_nav(4)))
        as_action.triggered.connect(lambda: (self.stack.setCurrentIndex(3), self.as_target.setText(ip), self._set_active_nav(3)))

        menu.addAction(portScan_action)
        menu.addAction(as_action)
        menu.addAction(ta_action)

        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _build_detail_panel(self):
        self.detail_panel = QWidget()
        self.detail_panel.setStyleSheet("background-color: #262626; border-left: 1px solid #3c3c3c;")
        layout = QVBoxLayout(self.detail_panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # Панель информации о выбранном устройстве.
        title = QLabel("ИНФОРМАЦИЯ ОБ УСТРОЙСТВЕ")
        title.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        layout.addWidget(title)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #3c3c3c;")
        layout.addWidget(sep)
        layout.addSpacing(8)

        self.detail_ip = QLabel("IP: —")
        self.detail_mac = QLabel("MAC: —")
        self.detail_hostname= QLabel("HOSTNAME: —")
        self.detail_vendor  = QLabel("VENDOR: —")
        self.detail_http = QLabel(self.i18n.t("detail_http"))
        self.detail_tls = QLabel(self.i18n.t("detail_tls"))
        self.detail_smb = QLabel(self.i18n.t("detail_smb"))
        self.detail_snmp = QLabel(self.i18n.t("detail_snmp"))
        self.detail_filtered = QLabel(self.i18n.t("detail_filtered"))
        self.detail_closed = QLabel("CLOSED: —")
        self.detail_discovery = QLabel("ОБНАРУЖЕНИЕ: —")
        self.detail_camera = QLabel("КАМЕРА: —")

        for label in [self.detail_ip, self.detail_mac, self.detail_hostname, self.detail_vendor,
                      self.detail_http, self.detail_tls, self.detail_smb, self.detail_snmp,
                      self.detail_filtered, self.detail_closed, self.detail_discovery, self.detail_camera]:
            label.setStyleSheet("color: #ffffff; font-size: 12px;")
            label.setWordWrap(True)
            layout.addWidget(label)

        layout.addSpacing(10)

        sep2 = QWidget()
        sep2.setFixedHeight(1)
        sep2.setStyleSheet("background-color: #3c3c3c;")
        layout.addWidget(sep2)
        layout.addSpacing(8)

        actions_row = QHBoxLayout()
        actions_label = QLabel("ДЕЙСТВИЯ")
        actions_label.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        actions_row.addWidget(actions_label)
        actions_row.addStretch()
        layout.addLayout(actions_row)
        layout.addSpacing(4)

        # Поле для ручного ввода IP/хоста для действий.
        self.detail_target_input = QLineEdit()
        self.detail_target_input.setPlaceholderText(self.i18n.t("detail_action_hint"))
        self.detail_target_input.setToolTip("Введите любой IP или хост: можно пинговать, трассировать и сканировать порты")
        self.detail_target_input.textChanged.connect(self._update_detail_actions_state)
        layout.addWidget(self.detail_target_input)
        target_hint = QLabel(self.i18n.t("detail_action_hint"))
        target_hint.setWordWrap(True)
        target_hint.setStyleSheet("color: #aaaaaa; font-size: 10px;")
        layout.addWidget(target_hint)
        layout.addSpacing(4)

        # Кнопки быстрых действий для выбранного устройства или введённой цели.
        self.btn_ping      = QPushButton("PING")
        self.btn_portscan  = QPushButton("СКАН ПОРТОВ")
        self.btn_traceroute = QPushButton("TRACEROUTE")

        self.btn_ping.clicked.connect(self._run_ping)
        self.btn_traceroute.clicked.connect(self._run_traceroute)
        self.btn_portscan.clicked.connect(self._go_to_scan)

        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        # Консоль вывода команд для выбранного устройства.
        self.output_box.setStyleSheet("""
            QTextEdit {
                background-color: #141414;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                font-size: 11px;
                padding: 8px;
                border-radius: 8px;
            }
        """)
        self.output_box.setPlaceholderText("// вывод команды")
        layout.addWidget(self.output_box, stretch=1)

        for btn in [self.btn_ping, self.btn_traceroute,self.btn_portscan]:
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            btn.setEnabled(False)
            layout.addWidget(btn)

        layout.addStretch()
        return self.detail_panel

    def _update_detail_actions_state(self):
        # Активация кнопок действий при выборе устройства или вводе IP.
        has_input = bool(self.detail_target_input.text().strip()) if hasattr(self, "detail_target_input") else False
        has_row = self.table.currentRow() >= 0
        enabled = has_input or has_row
        for btn in [self.btn_ping, self.btn_portscan, self.btn_traceroute]:
            btn.setEnabled(enabled)

    def _on_device_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return

        row = self.table.currentRow()
        ip       = self.table.item(row, 0).text()
        mac      = self.table.item(row, 1).text()
        vendor   = self.table.item(row, 2).text()
        hostname = self.table.item(row, 3).text()

        host = None
        for h in getattr(self, "last_hosts", []) or []:
            if h.get("ip") == ip:
                host = h
                break

        discovery = (host or {}).get("discovery", "")
        mac_display = mac
        if (not mac or mac == "-") and discovery == "tcp":
            mac_display = "неизвестен (обнаружено по TCP)"
        self.detail_ip.setText(f"IP: {ip}")
        self.detail_mac.setText(f"MAC: {mac_display}")
        self.detail_vendor.setText(f"VENDOR: {vendor}")
        self.detail_hostname.setText(f"HOSTNAME: {hostname}")
        self.detail_http.setText(f"HTTP (признак): {(host or {}).get('http_title') or '—'}")
        self.detail_tls.setText(f"TLS (признак): {(host or {}).get('tls_cert') or '—'}")
        self.detail_smb.setText(f"SMB (признак): {(host or {}).get('smb_info') or '—'}")
        self.detail_snmp.setText(f"SNMP (признак): {(host or {}).get('snmp_desc') or '—'}")
        filtered = (host or {}).get("filtered_ports") or []
        closed = (host or {}).get("closed_ports") or []
        discovery = (host or {}).get("discovery") or "—"
        self.detail_filtered.setText(f"FILTERED/NO-RESPONSE (признак): {', '.join(map(str, filtered)) if filtered else '—'}")
        self.detail_closed.setText(f"CLOSED: {', '.join(map(str, closed)) if closed else '—'}")
        self.detail_discovery.setText(f"ОБНАРУЖЕНИЕ: {discovery}")
        self.detail_camera.setText(f"КАМЕРА: {(host or {}).get('camera_hint') or '—'}")
        if hasattr(self, "detail_target_input") and not self.detail_target_input.text().strip():
            self.detail_target_input.setPlaceholderText(f"IP/хост для действий (выбран: {ip})")
        self._update_detail_actions_state()

    def _start_scan(self):
        # Запуск сетевого сканирования через очередь задач.
        self._enqueue_task("Сканирование сети", self._run_network_scan)

    def _run_network_scan(self):
        target = self._resolve_subnet()
        if not target:
            self.statusBar().showMessage("Подсеть недоступна - выберите интерфейс с IP или введите подсеть вручную.")
            self._finish_task("Сканирование сети")
            return

        self.scan_button.setEnabled(False)
        self.btn_export_graph.setEnabled(False)
        self.scan_progress.start()
        self.table.setRowCount(0)
        self.subnet_label.setText(target)

        if is_target_fully_local(target):
            self.statusBar().showMessage("Сканирование...")
            self.worker = ScanWorker(target)
        else:
            self.statusBar().showMessage("Scanning routed range (traceroute cartography)...")
            self.worker = RangeScanWorker(target)
        self.worker.finished.connect(self._on_scan_finished)
        self.worker.start()

    def _populate_table(self, hosts):
        for d in hosts:
            row = self.table.rowCount()
            self.table.insertRow(row)
            mac = d.get("mac", "")
            if not mac and d.get("discovery") == "tcp":
                mac = "неизвестен (TCP)"
            self.table.setItem(row, 0, QTableWidgetItem(d.get("ip", "")))
            self.table.setItem(row, 1, QTableWidgetItem(mac))
            self.table.setItem(row, 2, QTableWidgetItem(d.get("vendor", "")))
            self.table.setItem(row, 3, QTableWidgetItem(d.get("hostname", "")))

    def _on_scan_finished(self, hosts):
        self._populate_table(hosts)
        events = self._record_scan_events(hosts)
        self.last_hosts = hosts
        try:
            self._save_scan_history(hosts)
        except Exception:
            logging.getLogger(__name__).exception("Failed to save scan history")
        # Обновление инвентаря и уведомление о новых устройствах.
        new_devices = []
        try:
            inv_before = self._load_inventory()
            known_keys = set(inv_before.keys())
            self._update_inventory_from_hosts(hosts)
            for h in hosts or []:
                key = (h.get("mac") or "").lower() or (h.get("ip") or "")
                if key and key not in known_keys:
                    new_devices.append(h.get("ip") or key)
            if new_devices:
                self.event_log.append(f"[{time.strftime('%H:%M:%S')}] Новые устройства: {', '.join(new_devices)}")
        except Exception:
            logging.getLogger(__name__).exception("Failed to update inventory")
        msg = f"{len(hosts)} устройств найдено."
        if events:
            msg += f" События: {len(events)}"
        if new_devices:
            msg += f" Новые: {len(new_devices)}"
        self.statusBar().showMessage(msg)
        self.scan_button.setEnabled(True)
        self.scan_progress.stop()
        self._update_graph(hosts)
        self.btn_export_graph.setDisabled(False)
        self._finish_task("Сканирование сети")

    def _build_topology(self, hosts: list) -> dict:
        subnet_str = self._resolve_subnet()

        gateway_ip = None
        gateway_candidates = []

        for host in hosts:
            ip = host.get("ip", "")
            hostname = (host.get("hostname") or "").lower()
            vendor = (host.get("vendor") or "").lower()
            if hostname in ("router", "gateway", "_gateway", "default-gateway"):
                gateway_ip = ip
                break
            if ip.endswith(".1") or ip.endswith(".254"):
                gateway_candidates.insert(0, ip) if ip.endswith(".1") else gateway_candidates.append(ip)

        if not gateway_ip and gateway_candidates:
            gateway_ip = gateway_candidates[0]

        subnets_map = {}
        if subnet_str:
            try:
                net = ipaddress.ip_network(subnet_str, strict=False)
                subnets_map[subnet_str] = {
                    "network": subnet_str,
                    "prefix": str(net.prefixlen),
                    "broadcast": str(net.broadcast_address),
                    "devices": [],
                }
            except Exception:
                logging.getLogger(__name__).debug("Failed to load host state for map", exc_info=True)

        for host in hosts:
            ip = host.get("ip", "")
            placed = False
            for snet_str, snet_data in subnets_map.items():
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(snet_str, strict=False):
                        snet_data["devices"].append(ip)
                        placed = True
                        break
                except Exception:
                    logging.getLogger(__name__).debug("Failed to place host in subnet", exc_info=True)
            if not placed and subnets_map:
                list(subnets_map.values())[0]["devices"].append(ip)

        intermediate_vendors = [
            "cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "dlink",
            "linksys", "tenda", "zyxel", "aruba", "juniper", "fortinet",
            "ruckus", "meraki", "extreme", "huawei", "h3c", "brocade",
        ]
        intermediate_hostnames = [
            "router", "ap", "wifi", "switch", "hub", "access-point",
            "access_point", "wlan", "gateway", "firewall", "proxy",
        ]

        intermediate_ips = set()
        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            vendor = (host.get("vendor") or "").lower()
            hostname = (host.get("hostname") or "").lower()
            if any(k in vendor for k in intermediate_vendors):
                intermediate_ips.add(ip)
                continue
            if any(k in hostname for k in intermediate_hostnames):
                intermediate_ips.add(ip)

        edges = []
        if gateway_ip:
            edges.append({"src": gateway_ip, "dst": "internet", "type": "uplink"})

        for host in hosts:
            ip = host.get("ip", "")
            if ip == gateway_ip:
                continue
            if host.get("router_hop"):
                continue
            if not gateway_ip:
                continue
            if ip in intermediate_ips:
                edges.append({"src": ip, "dst": gateway_ip, "type": "backbone"})
            else:
                parent = gateway_ip
                for inter_ip in intermediate_ips:
                    inter_host = next((h for h in hosts if h.get("ip") == inter_ip), None)
                    if not inter_host:
                        continue
                    inter_vendor = (inter_host.get("vendor") or "").lower()
                    inter_hostname = (inter_host.get("hostname") or "").lower()
                    if any(k in inter_vendor for k in ["tp-link", "netgear", "dlink", "linksys",
                                                        "tenda", "zyxel", "aruba", "ubiquiti",
                                                        "ruckus", "meraki"]) or                        any(k in inter_hostname for k in ["ap", "wifi", "wlan", "access"]):
                        try:
                            host_net = ipaddress.ip_address(ip)
                            inter_net = ipaddress.ip_address(inter_ip)
                            host_parts = str(host_net).split(".")
                            inter_parts = str(inter_net).split(".")
                            if host_parts[:3] == inter_parts[:3]:
                                parent = inter_ip
                                break
                        except Exception:
                            logging.getLogger(__name__).debug("Failed to detect parent subnet", exc_info=True)
                edges.append({"src": ip, "dst": parent, "type": "client"})

        router_hosts = {}
        seen_router_edges = set()
        existing_ips = {h.get("ip") for h in hosts}

        for host in hosts:
            hop = host.get("router_hop")
            host_ip = host.get("ip")
            if not hop or hop == host_ip:
                continue
            if hop not in existing_ips and hop not in router_hosts:
                router_hosts[hop] = {
                    "ip": hop,
                    "mac": "",
                    "hostname": hop,
                    "vendor": "",
                    "ttl": None,
                    "os_hint": "unknown",
                    "open_ports": [],
                    "role": "router",
                    "snmp_desc": "",
                    "embedded_device": "",
                }
            parent = gateway_ip or "internet"
            if (hop, parent) not in seen_router_edges:
                edges.append({"src": hop, "dst": parent, "type": "backbone"})
                seen_router_edges.add((hop, parent))
            if (host_ip, hop) not in seen_router_edges:
                edges.append({"src": host_ip, "dst": hop, "type": "client"})
                seen_router_edges.add((host_ip, hop))

        return {
            "devices": hosts + list(router_hosts.values()),
            "gateway": gateway_ip,
            "subnet": subnet_str,
            "subnets": list(subnets_map.values()),
            "edges": edges,
            "intermediates": list(intermediate_ips),
        }

    def _update_graph(self, hosts):
        if not hasattr(self, 'graph_view'):
            return
        if not self.graph_ready:
            self._pending_graph_data = hosts
            return
        topology = self._build_topology(hosts)
        data = json.dumps(topology, ensure_ascii=False)
        lang = getattr(getattr(self, 'i18n', None), 'lang', 'ru')
        # Передаём JSON как объект JS, чтобы избежать проблем с экранированием.
        self.graph_view.page().runJavaScript(f"updateGraph({data}); setGraphLang('{lang}')")

    def _get_detail_target(self):
        # Цель для действий: ручной ввод или выбранное устройство.
        manual = self.detail_target_input.text().strip() if hasattr(self, "detail_target_input") else ""
        if manual:
            return manual
        row = self.table.currentRow()
        if row >= 0:
            return self.table.item(row, 0).text()
        return ""

    def _go_to_scan(self):
        target = self._get_detail_target()
        if not target:
            return
        self._set_active_nav(1)
        self.current_target_ip = target
        self.scan_target.setText(target)
        self.stack.setCurrentIndex(1)

    def _run_ping(self):
        ip = self._get_detail_target()
        if not ip:
            return
        if not is_valid_target(ip) or "/" in ip or re.match(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$", ip):
            self.output_box.clear()
            self.output_box.append("// error: укажите IP или hostname")
            return

        self.output_box.clear()
        self.output_box.append(f"// ping {ip}\n")

        # Команда ping для Windows.
        cmd = ["ping", "-n", "4", ip]

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(
            lambda: self.output_box.append("\n// done.")
        )
        self.action_worker.start()

    def _run_traceroute(self):
        ip = self._get_detail_target()
        if not ip:
            return
        if not is_valid_target(ip) or "/" in ip or re.match(r"^\d{1,3}(\.\d{1,3}){3}-\d{1,3}$", ip):
            self.output_box.clear()
            self.output_box.append("// error: укажите IP или hostname")
            return

        self.output_box.clear()
        self.output_box.append(f"// traceroute {ip}\n")

        self.btn_traceroute.setText("STOP")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._stop_action)

        # Команда traceroute для Windows.
        cmd = ["tracert", ip]

        self.action_worker = ActionWorker(cmd)
        self.action_worker.output.connect(self.output_box.append)
        self.action_worker.finished.connect(self._on_action_finished)
        self.action_worker.start()

    def _stop_action(self):
        if hasattr(self, 'action_worker') and self.action_worker.isRunning():
            try:
                self.action_worker.finished.disconnect()
            except Exception:
                logging.getLogger(__name__).debug("Failed to disconnect action worker", exc_info=True)
            self.action_worker.stop()
            self.action_worker.wait(3000)
        self.output_box.append("\n// interrupted.")
        self.btn_traceroute.setText("TRACEROUTE")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)

    def _on_action_finished(self):
        self.output_box.append("\n// done.")
        self.btn_traceroute.setText("TRACEROUTE")
        self.btn_traceroute.clicked.disconnect()
        self.btn_traceroute.clicked.connect(self._run_traceroute)


    def _build_settings_page(self):
        # Страница настроек программы.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        self.settings_title_label = QLabel(self.i18n.t("settings_title"))
        self.settings_title_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: 700;")
        layout.addWidget(self.settings_title_label)

        card = QFrame()
        card.setStyleSheet("QFrame { background-color: #252526; border: 1px solid #3c3c3c; border-radius: 10px; }")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(8)

        self.settings_lang_label = QLabel(self.i18n.t("settings_language"))
        self.settings_lang_label.setStyleSheet("color: #ffffff; font-size: 14px; font-weight: 600; border: none;")
        card_layout.addWidget(self.settings_lang_label)

        self.settings_lang_hint = QLabel(self.i18n.t("settings_language_hint"))
        self.settings_lang_hint.setStyleSheet("color: #b0b0b0; font-size: 12px; border: none;")
        self.settings_lang_hint.setWordWrap(True)
        card_layout.addWidget(self.settings_lang_hint)

        self.lang_combo = QComboBox()
        self.lang_combo.addItem("Русский", "ru")
        self.lang_combo.addItem("English", "en")
        idx = self.lang_combo.findData(self.i18n.lang)
        if idx >= 0:
            self.lang_combo.setCurrentIndex(idx)
        self.lang_combo.currentIndexChanged.connect(self._on_language_changed)
        self.lang_combo.setFixedWidth(220)
        card_layout.addWidget(self.lang_combo)
        card_layout.addStretch()
        layout.addWidget(card)
        layout.addStretch()
        return page

    def _on_language_changed(self):
        # Обработчик смены языка из настроек.
        lang = self.lang_combo.currentData() if hasattr(self, "lang_combo") else "ru"
        if lang not in ("ru", "en") or lang == self.i18n.lang:
            return
        self.i18n.set_lang(lang)
        self.settings.setValue("language", lang)
        self.apply_language()

    def _build_help_page(self):
        # Страница справки: описание всех разделов и функций программы.
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        self.help_title_label = QLabel("Справка по функциям Eptal-Analyzer" if self.i18n.lang == "ru" else "Eptal-Analyzer Help Guide")
        self.help_title_label.setStyleSheet("color: #ffffff; font-size: 24px; font-weight: 700;")
        layout.addWidget(self.help_title_label)

        self.help_subtitle_label = QLabel(self.i18n.t("help_subtitle"))
        self.help_subtitle_label.setWordWrap(True)
        self.help_subtitle_label.setStyleSheet("color: #b0b0b0; font-size: 13px;")
        layout.addWidget(self.help_subtitle_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; }")
        self.help_content = QWidget()
        self.help_content_layout = QVBoxLayout(self.help_content)
        self.help_content_layout.setContentsMargins(0, 0, 8, 0)
        self.help_content_layout.setSpacing(10)
        self._populate_help_page()
        scroll.setWidget(self.help_content)
        layout.addWidget(scroll, stretch=1)
        return page

    def _populate_help_page(self):
        # Заполнение справки с учётом текущего языка.
        layout = getattr(self, "help_content_layout", None)
        if layout is None:
            return
        while layout.count():
            item = layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()
            sub = item.layout()
            if sub is not None:
                while sub.count():
                    si = sub.takeAt(0)
                    sw = si.widget()
                    if sw is not None:
                        sw.deleteLater()

        assets = os.path.join(os.path.dirname(__file__), "../img", "icons")
        lang = self.i18n.lang
        ru_sections = [
            ("home.svg", "Главная", [
                "Обзор сети: найденные устройства, быстрые действия и сводка по состоянию.",
                "Запуск сканирования, переход к карте, диагностике, инвентарю и журналу.",
                "Быстрый доступ к истории, отчётам и основным операциям.",
            ]),
            ("eye.svg", "Сканирование портов", [
                "Цель: IP, CIDR, диапазон или hostname. Можно сохранять профили целей.",
                "Режимы сканирования: -F (быстрый, популярные порты), -sS (SYN, полуоткрытый), -sT (TCP connect), -sU (UDP), -sN (NULL), -sX (Xmas), -p- (все 65535 портов), -A (агрессивный: ОС/версии/скрипты/traceroute), -Pn (не делать ping перед сканом).",
                "Определение: -sV (версии сервисов), -O (определение ОС), --osscan-guess (угадывать ОС агрессивнее).",
                "Скрипты NSE: -sC (стандартные безопасные), --script banner (баннер сервиса), --script safe (безопасные), --script vuln (проверка известных уязвимостей), --script vulners (CVE по версии), --script malware (признаки malware/backdoor), --script discovery (доп. обнаружение).",
                "HTTP/SSL/SMB/DNS/FTP/SSH скрипты: http-enum (пути/директории), http-headers (заголовки), http-methods (разрешённые методы), ssl-cert (сертификат), ssl-enum-ciphers (шифры), smb-enum-shares (SMB-шары), smb-enum-users (SMB-пользователи), dns-brute (поддомены), ftp-anon (анонимный FTP), ssh-auth-methods (методы SSH-авторизации).",
                "Вывод: --open (только открытые), -v (подробно), --reason (причина состояния порта).",
                "Тайминг: -T1 медленный/скрытный ... -T5 очень быстрый/шумный; -T3 обычный.",
                "Можно добавить свои флаги в поле пользовательских параметров. Рискованные флаги помечаются предупреждением.",
                "Экспорт результата сканирования и работа через очередь задач.",
            ]),
            ("network2.svg", "Карта сети", [
                "Графическое отображение обнаруженных устройств и связей.",
                "Помогает визуально оценить топологию и расположение узлов.",
                "Использует результаты сканирования и данные об устройствах.",
            ]),
            ("attack.svg", "Поверхность атаки", [
                "Анализ открытых сервисов, рисков и потенциальных уязвимостей.",
                "Показывает порты, сервисы, риск-оценки и признаки проблем.",
                "Используется для аудита внешней/внутренней поверхности хоста.",
            ]),
            ("traffic.svg", "Анализ трафика", [
                "Захват пакетов в реальном времени (Scapy/Npcap, обычно нужны права администратора).",
                "Фильтры: текстовый фильтр, выбор устройства, BPF-фильтр.",
                "PCAP: выбор файла и запись захвата в PCAP.",
                "Статистика: top proto/port/top source, количество flows, предупреждение об аномалии доминирующего источника.",
                "Таблица пакетов с колонкой Инфо (простые DNS/HTTP признаки), экспорт CSV.",
            ]),
            ("diagnostics.svg", "Диагностика сети", [
                "Проверка адаптера, Wi-Fi, DHCP/DNS, шлюза, интернета и MTU.",
                "Быстрая оценка состояния локальной сети и подключения.",
                "Полезна при проблемах с доступностью, DNS или маршрутизацией.",
            ]),
            ("inventory.svg", "Журнал и инвентарь", [
                "Список устройств, история появления, изменения и метки.",
                "Уведомления о новых устройствах и изменениях.",
                "Очистка инвентаря/журнала при необходимости.",
            ]),
            ("monitoring.svg", "Мониторинг доступности", [
                "Проверка доступности шлюза/узлов/целей по расписанию или вручную.",
                "История проверок, статусы OK/FAIL, детали ошибок.",
                "Экспорт и очистка журнала мониторинга.",
            ]),
            ("audit.svg", "Аудит безопасности", [
                "Сводка рисков, открытых/filtered портов, признаков IoT/камер и уязвимостей.",
                "Экспорт аудита в TXT/CSV.",
                "Эвристики и признаки помечаются как требующие подтверждения.",
            ]),
            ("help.svg", "Справка", [
                "Этот раздел: описание всех функций и элементов боковой панели.",
                "Используйте его как быстрое руководство по программе.",
            ]),
        ]
        en_sections = [
            ("home.svg", "Home", [
                "Network overview: discovered devices, quick actions, and status summary.",
                "Start scans, navigate to map, diagnostics, inventory, and journal.",
                "Quick access to history, reports, and main operations.",
            ]),
            ("eye.svg", "Port Scan", [
                "Target: IP, CIDR, range, or hostname. You can save target profiles.",
                "Scan modes: -F (fast, common ports), -sS (SYN/half-open), -sT (TCP connect), -sU (UDP), -sN (NULL), -sX (Xmas), -p- (all 65535 ports), -A (aggressive: OS/versions/scripts/traceroute), -Pn (skip host discovery ping).",
                "Detection: -sV (service versions), -O (OS detection), --osscan-guess (more aggressive OS guessing).",
                "NSE scripts: -sC (default safe), --script banner (service banner), --script safe (safe), --script vuln (known vulnerability checks), --script vulners (CVE by version), --script malware (malware/backdoor indicators), --script discovery (additional discovery).",
                "HTTP/SSL/SMB/DNS/FTP/SSH scripts: http-enum (paths/directories), http-headers (headers), http-methods (allowed methods), ssl-cert (certificate), ssl-enum-ciphers (ciphers), smb-enum-shares (SMB shares), smb-enum-users (SMB users), dns-brute (subdomains), ftp-anon (anonymous FTP), ssh-auth-methods (SSH auth methods).",
                "Output: --open (open only), -v (verbose), --reason (port state reason).",
                "Timing: -T1 slow/stealthy ... -T5 very fast/noisy; -T3 normal.",
                "You can add custom flags in the user parameters field. Risky flags are marked with a warning.",
                "Scan result export and task queue support.",
            ]),
            ("network2.svg", "Network Map", [
                "Visual graph of discovered devices and connections.",
                "Helps assess topology and node placement visually.",
                "Uses scan results and device data.",
            ]),
            ("attack.svg", "Attack Surface", [
                "Analysis of open services, risks, and potential vulnerabilities.",
                "Shows ports, services, risk scores, and problem indicators.",
                "Used for auditing host external/internal surface.",
            ]),
            ("traffic.svg", "Traffic Analysis", [
                "Real-time packet capture (Scapy/Npcap, usually requires administrator rights).",
                "Filters: text filter, device selection, BPF filter.",
                "PCAP: file selection and capture writing to PCAP.",
                "Stats: top proto/port/top source, flow count, dominant-source anomaly warning.",
                "Packet table with Info column (simple DNS/HTTP indicators), CSV export.",
            ]),
            ("diagnostics.svg", "Network Diagnostics", [
                "Checks adapter, Wi-Fi, DHCP/DNS, gateway, internet, and MTU.",
                "Quick assessment of local network and connectivity state.",
                "Useful for availability, DNS, or routing issues.",
            ]),
            ("inventory.svg", "Journal & Inventory", [
                "Device list, appearance history, changes, and tags.",
                "Notifications about new devices and changes.",
                "Clear inventory/journal when needed.",
            ]),
            ("monitoring.svg", "Availability Monitoring", [
                "Checks gateway/hosts/targets availability on schedule or manually.",
                "Check history, OK/FAIL statuses, error details.",
                "Export and clear monitoring log.",
            ]),
            ("audit.svg", "Security Audit", [
                "Risk summary, open/filtered ports, IoT/camera and vulnerability indicators.",
                "Audit export to TXT/CSV.",
                "Heuristics and indicators are marked as requiring confirmation.",
            ]),
            ("help.svg", "Help", [
                "This section: description of all features and sidebar elements.",
                "Use it as a quick guide to the program.",
            ]),
        ]
        sections = en_sections if lang == "en" else ru_sections

        for icon_file, name, items in sections:
            card = QFrame()
            card.setStyleSheet("QFrame { background-color: #252526; border: 1px solid #3c3c3c; border-radius: 10px; }")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(12, 12, 12, 12)
            card_layout.setSpacing(12)

            icon_label = QLabel()
            icon_path = os.path.join(assets, icon_file)
            icon_label.setPixmap(load_colored_svg(icon_path, "#79a7ff", size=28).pixmap(QSize(28, 28)))
            icon_label.setFixedSize(32, 32)
            icon_label.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)
            card_layout.addWidget(icon_label)

            text_box = QVBoxLayout()
            text_box.setSpacing(4)
            name_label = QLabel(name)
            name_label.setStyleSheet("color: #ffffff; font-size: 15px; font-weight: 700; border: none;")
            text_box.addWidget(name_label)
            for item in items:
                bullet = QLabel(f"• {item}")
                bullet.setWordWrap(True)
                bullet.setStyleSheet("color: #cccccc; font-size: 12px; border: none;")
                text_box.addWidget(bullet)
            card_layout.addLayout(text_box, stretch=1)
            layout.addWidget(card)

        layout.addStretch()
    def _build_attackSurface_page(self):
        self.scanning = False
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        left = QWidget()
        left.setFixedWidth(240)
        left.setStyleSheet("background-color: #252526; border-right: 1px solid #3c3c3c;")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(10, 10, 10, 10)
        left_layout.setSpacing(6)

        as_label = QLabel("ЦЕЛЬ")
        as_label.setStyleSheet("color: #ffffff; font-size: 11px; letter-spacing: 2px;")
        left_layout.addWidget(as_label)

        self.as_target = QLineEdit()
        self.as_target.setPlaceholderText("192.168.1.1")
        self.as_target.setStyleSheet("""
            QLineEdit {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3c3c3c;
                padding: 6px;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
                font-size: 11px;
                border-radius: 8px;
            }
            QLineEdit:focus { border-color: #ffffff; }
        """)
        left_layout.addWidget(self.as_target)

        # Кнопка анализа поверхности атаки.
        self.as_scan_btn = QPushButton("АНАЛИЗ")
        self.as_scan_btn.setDisabled(True)
        self.as_scan_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_scan_btn.setStyleSheet("""
            QPushButton { border: 1px solid #5a5a5a !important;     border-radius: 8px;
            }
        """)
        self.as_scan_btn.clicked.connect(self._as_start_scan)
        left_layout.addWidget(self.as_scan_btn)

        def _on_as_target_changed(text):
            valid = is_valid_target(text)
            self.as_scan_btn.setDisabled(not valid or self.scanning)
            if not text:
                self.as_target.setStyleSheet("""
                    QLineEdit {
                        background-color: #2b2b2b;
                        color: #ffffff;
                        border: 1px solid #3c3c3c;
                        padding: 6px;
                        font-family: 'Consolas', 'JetBrains Mono', monospace;
                        font-size: 11px;
                        border-radius: 8px;
            }
                    QLineEdit:focus { border-color: #ffffff; }
                """)
            elif valid:
                self.as_target.setStyleSheet("""
                    QLineEdit {
                        background-color: #2b2b2b;
                        color: #ffffff;
                        border: 1px solid #909090;
                        padding: 6px;
                        font-family: 'Consolas', 'JetBrains Mono', monospace;
                        font-size: 11px;
                        border-radius: 8px;
            }
                """)
            else:
                self.as_target.setStyleSheet("""
                    QLineEdit {
                        background-color: #2b2b2b;
                        color: #ff4444;
                        border: 1px solid #ff4444;
                        padding: 6px;
                        font-family: 'Consolas', 'JetBrains Mono', monospace;
                        font-size: 11px;
                        border-radius: 8px;
            }
                """)

        self.as_target.textChanged.connect(_on_as_target_changed)

        # Кнопка экспорта результатов поверхности атаки.
        self.as_export_btn = QPushButton(self.i18n.t("export_csv"))
        self.as_export_btn.setDisabled(True)
        self.as_export_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_export_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #ffffff;
                border: 1px solid #909090;
                padding: 6px 18px;
                font-weight: 500;
                letter-spacing: 1px;
                border-radius: 8px;
            }
            QPushButton:disabled { color: #c0c0c0; border-color: #222; }
        """)
        self.as_export_btn.clicked.connect(self._as_export_csv)
        left_layout.addWidget(self.as_export_btn)

        self.as_progress_bar = QProgressBar()
        self.as_progress_bar.setRange(0, 100)
        self.as_progress_bar.setValue(0)
        self.as_progress_bar.setTextVisible(True)
        self.as_progress_bar.setFormat("%p%")
        self.as_progress_bar.setFixedHeight(16)
        self.as_progress_bar.setVisible(False)
        self.as_progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #2b2b2b;
                border: 1px solid #3c3c3c;
                border-radius: 6px;
                text-align: center;
                color: #ffffff;
                font-size: 9px;
                font-family: 'Consolas', 'JetBrains Mono', monospace;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #003322, stop:1 #5a5a5a
                );
                border-radius: 6px;
            }
        """)
        left_layout.addWidget(self.as_progress_bar)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #3c3c3c; margin-top: 4px; margin-bottom: 4px;")
        left_layout.addWidget(sep)

        history_label = QLabel(self.i18n.t("btn_history"))
        history_label.setStyleSheet("color: #d0d0d0; font-size: 10px; letter-spacing: 2px;")
        left_layout.addWidget(history_label)

        self.as_history = QTableWidget()
        self.as_history.setColumnCount(2)
        self.as_history.setHorizontalHeaderLabels([self.i18n.t("target").upper(), self.i18n.t("col_risk")])
        self.as_history.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.as_history.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_history.setColumnWidth(1, 75)
        self.as_history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_history.verticalHeader().setVisible(False)
        self.as_history.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_history.itemClicked.connect(self._as_load_from_history)
        self.as_history.setStyleSheet("""
            QTableWidget { background-color: #252526; border: none; }
            QTableWidget::item:selected { color: #ffffff; }
        """)
        left_layout.addWidget(self.as_history, stretch=1)

        self._as_results = {}
        layout.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self.as_header = QLabel("// поверхность атаки - выберите цель")
        self.as_header.setFixedHeight(36)
        self.as_header.setStyleSheet("""
            background-color: #252526;
            color: #d0d0d0;
            font-size: 11px;
            padding: 0px 12px;
            border-bottom: 1px solid #3c3c3c;
        """)
        right_layout.addWidget(self.as_header)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setStyleSheet("QSplitter::handle { background-color: #3c3c3c; }")

        ports_container = QWidget()
        ports_layout = QVBoxLayout(ports_container)
        ports_layout.setContentsMargins(0, 0, 0, 0)
        ports_layout.setSpacing(0)

        ports_label = QLabel("  ОТКРЫТЫЕ ПОРТЫ")
        ports_label.setFixedHeight(24)
        ports_label.setStyleSheet("background-color: #262626; color: #d0d0d0; font-size: 10px; letter-spacing: 2px; border-bottom: 1px solid #111;")
        ports_layout.addWidget(ports_label)

        self.as_ports_table = QTableWidget()
        self.as_ports_table.setColumnCount(5)
        self.as_ports_table.setHorizontalHeaderLabels([self.i18n.t("col_port"), self.i18n.t("col_proto"), self.i18n.t("col_service"), self.i18n.t("col_version"), self.i18n.t("col_risk")])
        self.as_ports_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(0, 80)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(1, 110)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(2, 110)
        self.as_ports_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.as_ports_table.setColumnWidth(4, 80)
        self.as_ports_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_ports_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_ports_table.verticalHeader().setVisible(False)
        self.as_ports_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        ports_layout.addWidget(self.as_ports_table)
        splitter.addWidget(ports_container)

        cve_container = QWidget()
        cve_layout = QVBoxLayout(cve_container)
        cve_layout.setContentsMargins(0, 0, 0, 0)
        cve_layout.setSpacing(0)

        cve_label = QLabel("  УЯЗВИМОСТИ / CVE")
        cve_label.setFixedHeight(24)
        cve_label.setStyleSheet("background-color: #262626; color: #d0d0d0; font-size: 10px; letter-spacing: 2px; border-bottom: 1px solid #111; border-top: 1px solid #111;")
        cve_layout.addWidget(cve_label)

        self.as_cve_table = QTableWidget()
        self.as_cve_table.setColumnCount(5)
        self.as_cve_table.setHorizontalHeaderLabels([self.i18n.t("col_cve"), self.i18n.t("col_cvss"), self.i18n.t("col_port"), self.i18n.t("col_service"), self.i18n.t("col_details")])
        self.as_cve_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(0, 140)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(1, 70)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(2, 75)
        self.as_cve_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.as_cve_table.setColumnWidth(3, 110)
        self.as_cve_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.as_cve_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.as_cve_table.verticalHeader().setVisible(False)
        self.as_cve_table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.as_cve_table.itemDoubleClicked.connect(self._as_open_cve)
        cve_layout.addWidget(self.as_cve_table)
        splitter.addWidget(cve_container)

        splitter.setSizes([300, 200])
        right_layout.addWidget(splitter, stretch=1)

        self.as_status = QLabel("// готово")
        self.as_status.setStyleSheet("""
            background-color: #252526;
            color: #c0c0c0;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)
        right_layout.addWidget(self.as_status)
        layout.addWidget(right, stretch=1)
        return page

    def _as_export_csv(self):
        target = self.as_target.text().strip()
        if not target or target not in self._as_results:
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Attack Surface",
            f"attack_surface_{target.replace('.', '_')}.csv",
            "CSV Files (*.csv);;All Files (*)"
        )
        if not path:
            return

        result = self._as_results[target]

        with open(path, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["TARGET", "OS", "PORTS_COUNT", "CVE_COUNT"])
            writer.writerow([
                result["target"],
                result["os"],
                len(result["ports"]),
                len(result["cves"])
            ])
            writer.writerow([])

            writer.writerow(["=== OPEN PORTS ==="])
            writer.writerow(["PORT", "PROTOCOL", "SERVICE", "VERSION", "RISK"])
            for p in result["ports"]:
                writer.writerow([p["port"], p["protocol"], p["service"], p["version"], p["risk"]])
            writer.writerow([])

            writer.writerow(["=== VULNERABILITIES / CVE ==="])
            writer.writerow(["CVE_ID", "CVSS", "PORT", "SERVICE", "DETAIL"])
            for c in result["cves"]:
                writer.writerow([c["id"], c["cvss"], c["port"], c["service"], c["detail"]])

        self.statusBar().showMessage(f"Attack surface exported to {path}")

    def _as_start_scan(self):
        # Запуск или остановка анализа поверхности атаки.
        if hasattr(self, "as_worker") and self.as_worker.isRunning():
            self._as_stop_scan()
            return
        self._enqueue_task("Attack Surface", self._do_as_start_scan)

    def _as_stop_scan(self):
        # Остановка анализа поверхности атаки.
        if hasattr(self, "as_worker") and self.as_worker.isRunning():
            self.as_worker.stop()
            self.as_worker.wait(3000)
        if hasattr(self, "_progress_timer"):
            self._progress_timer.stop()
        self.scanning = False
        self.as_target.setDisabled(False)
        self.as_scan_btn.setEnabled(True)
        self.as_scan_btn.setText("АНАЛИЗ")
        self.as_status.setText("// interrupted")
        self.as_progress_bar.setVisible(False)
        self._finish_task("Attack Surface")

    def _do_as_start_scan(self):
        if hasattr(self, "as_worker") and self.as_worker.isRunning():
            self.as_status.setText("// error: сканирование поверхности атаки уже выполняется")
            self._finish_task("Attack Surface")
            return
        target = self.as_target.text().strip()
        if not target or not is_valid_target(target):
            self.as_status.setText("// error: invalid target — use a valid IP, CIDR or hostname")
            self.as_status.setStyleSheet("""
                background-color: #252526;
                color: #ff4444;
                font-size: 10px;
                padding: 4px 12px;
                border-top: 1px solid #3c3c3c;
            """)
            self._finish_task("Attack Surface")
            return
        self.scanning = True
        self.as_target.setDisabled(True)
        self.as_scan_btn.setEnabled(True)
        self.as_scan_btn.setText("ОСТАНОВИТЬ")
        self.as_ports_table.setRowCount(0)
        self.as_cve_table.setRowCount(0)
        self.as_status.setText(f"// scanning {target}...")
        self.as_status.setStyleSheet("""
            background-color: #252526;
            color: #ffffff;
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)
        self.as_progress_bar.setValue(0)
        self.as_progress_bar.setVisible(True)
        def _tick():
            v = self.as_progress_bar.value()
            if v < 94:
                remaining = 94 - v
                step = max(1, remaining // 12)
                self.as_progress_bar.setValue(v + step)
        self._progress_timer = QTimer(self)
        self._progress_timer.setInterval(2000)
        self._progress_timer.timeout.connect(_tick)
        self._progress_timer.start()
        self.as_worker = AttackSurfaceWorker(target)
        self.as_worker.status_update.connect(self.as_status.setText)
        self.as_worker.port_found.connect(self._as_add_port_realtime)
        self.as_worker.finished.connect(self._as_on_finished)
        self.as_worker.start()

    def _as_add_port_realtime(self, port: dict):
        risk_colors = {"CRITICAL":"#ff0000","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#5a5a5a"}
        row = self.as_ports_table.rowCount()
        self.as_ports_table.insertRow(row)
        self.as_ports_table.setItem(row, 0, QTableWidgetItem(port["port"]))
        self.as_ports_table.setItem(row, 1, QTableWidgetItem(port["protocol"]))
        self.as_ports_table.setItem(row, 2, QTableWidgetItem(port["service"]))
        self.as_ports_table.setItem(row, 3, QTableWidgetItem(port["version"]))
        risk_item = QTableWidgetItem(port["risk"])
        risk_item.setForeground(QColor(risk_colors.get(port["risk"], "#aaaaaa")))
        self.as_ports_table.setItem(row, 4, risk_item)

    def _as_on_finished(self, result: dict):
        if hasattr(self, '_progress_timer'):
            self._progress_timer.stop()
        self.as_progress_bar.setValue(100)

        self.scanning = False
        self.as_target.setDisabled(False)
        self.as_scan_btn.setEnabled(True)
        self.as_scan_btn.setText("АНАЛИЗ")

        QTimer.singleShot(700, lambda: self.as_progress_bar.setVisible(False))

        # Если сканирование остановлено пользователем, не перезаписываем результат.
        if hasattr(self, "as_worker") and getattr(self.as_worker, "_stop_requested", False):
            self.as_status.setText("// interrupted")
            return

        self.as_ports_table.setRowCount(0)
        target = result["target"]
        self._as_results[target] = result
        self._as_display(result)
        self._as_update_history(target, result)
        self.as_export_btn.setEnabled(True)
        self._finish_task("Attack Surface")

    def _as_display(self, result: dict):
        target = result["target"]
        os_info = result["os"]
        port_count = len(result["ports"])
        cve_count = len(result["cves"])

        self.as_header.setText(
            f"// {target}  —  OS: {os_info}  —  {port_count} ports  —  {cve_count} CVE"
        )
        self.as_header.setStyleSheet("""
            background-color: #252526;
            color: #ffffff;
            font-size: 11px;
            padding: 0px 12px;
            border-bottom: 1px solid #3c3c3c;
        """)

        risk_colors = {"CRITICAL":"#ff2222","HIGH": "#ff4444", "MEDIUM": "#ff9900", "LOW": "#5a5a5a"}
        self.as_ports_table.setRowCount(0)
        for p in result["ports"]:
            row = self.as_ports_table.rowCount()
            self.as_ports_table.insertRow(row)
            self.as_ports_table.setItem(row, 0, QTableWidgetItem(p["port"]))
            self.as_ports_table.setItem(row, 1, QTableWidgetItem(p["protocol"]))
            self.as_ports_table.setItem(row, 2, QTableWidgetItem(p["service"]))
            self.as_ports_table.setItem(row, 3, QTableWidgetItem(p["version"]))
            risk_item = QTableWidgetItem(p["risk"])
            risk_item.setForeground(QColor(risk_colors.get(p["risk"], "#aaaaaa")))
            self.as_ports_table.setItem(row, 4, risk_item)

        self.as_cve_table.setRowCount(0)
        for c in result["cves"]:
            row = self.as_cve_table.rowCount()
            self.as_cve_table.insertRow(row)
            cve_item = QTableWidgetItem(c["id"])
            cve_item.setForeground(QColor("#4488ff"))
            cve_item.setData(Qt.ItemDataRole.UserRole, f"https://nvd.nist.gov/vuln/detail/{c['id']}")
            self.as_cve_table.setItem(row,0,cve_item)
            cvss = c["cvss"]
            cvss_item = QTableWidgetItem(str(cvss))
            if cvss >= 9.0:
                cvss_item.setForeground(QColor("#ff2222"))
            elif cvss >= 7.0:
                cvss_item.setForeground(QColor("#ff6600"))
            elif cvss >= 4.0:
                cvss_item.setForeground(QColor("#ffaa00"))
            else:
                cvss_item.setForeground(QColor("#888888"))
            self.as_cve_table.setItem(row, 1, cvss_item)
            self.as_cve_table.setItem(row, 2, QTableWidgetItem(c["port"]))
            self.as_cve_table.setItem(row, 3, QTableWidgetItem(c["service"]))
            self.as_cve_table.setItem(row, 4, QTableWidgetItem(c["detail"]))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            if max_cvss >= 9.0:
                risk_summary = "CRITICAL"
                color = "#ff2222"
            elif max_cvss >= 7.0:
                risk_summary = "HIGH"
                color = "#ff6600"
            elif max_cvss >= 4.0:
                risk_summary = "MEDIUM"
                color = "#ffaa00"
            else:
                risk_summary = "LOW"
                color = "#5a5a5a"
        elif result["ports"]:
            high_ports = [p for p in result["ports"] if p["risk"] == "HIGH"]
            risk_summary = "HIGH" if high_ports else "LOW"
            color = "#ff4444" if high_ports else "#5a5a5a"
        else:
            risk_summary = "CLEAN"
            color = "#5a5a5a"

        self.as_status.setText(f"// scan complete — max risk: {risk_summary}")
        self.as_status.setStyleSheet(f"""
            background-color: #252526;
            color: {color};
            font-size: 10px;
            padding: 4px 12px;
            border-top: 1px solid #3c3c3c;
        """)

    def _as_open_cve(self, item):
        if item.column() != 0:
            return
        url = item.data(Qt.ItemDataRole.UserRole)
        if not url:
            return

        # Открытие ссылки в Windows.
        QDesktopServices.openUrl(QUrl(url))

    def _as_update_history(self, target: str, result: dict):
        for row in range(self.as_history.rowCount()):
            if self.as_history.item(row, 0).text() == target:
                self.as_history.removeRow(row)
                break

        row = 0
        self.as_history.insertRow(row)
        self.as_history.setItem(row, 0, QTableWidgetItem(target))

        if result["cves"]:
            max_cvss = result["cves"][0]["cvss"]
            risk = "CRIT" if max_cvss >= 9 else "HIGH" if max_cvss >= 7 else "MED"
            color = "#ff2222" if max_cvss >= 9 else "#ff6600" if max_cvss >= 7 else "#ffaa00"
        elif any(p["risk"] == "HIGH" for p in result["ports"]):
            risk, color = "HIGH", "#ff4444"
        else:
            risk, color = "LOW", "#5a5a5a"

        risk_item = QTableWidgetItem(risk)
        risk_item.setForeground(QColor(color))
        risk_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.as_history.setItem(row, 1, risk_item)

    def _as_load_from_history(self, item):
        row = item.row()
        target = self.as_history.item(row, 0).text()
        if target in self._as_results:
            self._as_display(self._as_results[target])


if __name__ == "__main__":
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = "--no-sandbox --disable-gpu --disable-software-rasterizer"
    os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
    app = QApplication(sys.argv)
    logo = LogoIniziale()
    logo.show()
    app.processEvents()
    window = MainWindow()
    QTimer.singleShot(2500, lambda: (logo.finish(window), window.show()))
    sys.exit(app.exec())
