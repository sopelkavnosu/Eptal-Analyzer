# Eptal-Analyzer

**Eptal-Analyzer** — форк проекта [L0p4Map](https://github.com/L0p4/L0p4Map), развиваемый как отдельная Windows-программа для сетевого анализа, диагностики и инвентаризации.

Проект сохраняет базовую идею L0p4Map, но получил новое имя, переработанный интерфейс, новые функции, исправления и улучшения надёжности.  
Атрибуция оригинальному автору и лицензия **GNU GPL v3.0 or later** сохранены (см. `LICENSE`).

---

## RU — Что сделано и что обновлено

### Основные обновления

#### 1. Ребрендинг и интерфейс
- Новое название: **Eptal-Analyzer**.
- Тёмно-серый современный UI, белый текст, скруглённые элементы, аккуратные кнопки.
- Версия вынесена в `core/version.py` (`v1.0.31`).
- В заголовке окна отображается версия, в верхней панели — название программы.
- На загрузочном экране указана база L0p4Map и текущая версия Eptal-Analyzer.

#### 2. Новые функции
- **Карта сети** — визуализация устройств и связей.
- **Диагностика сети** — адаптер, Wi-Fi, DHCP/DNS, шлюз, интернет, MTU.
- **Ping / Traceroute / сканирование портов по любому IP** — можно ввести любой IP-адрес или хост и выполнить проверку доступности (ping), трассировку маршрута (traceroute) и сканирование портов/сервисов через Nmap.
- **Инвентарь и журнал** — данные об устройствах, история появления, события/изменения.
- **История сканирований и сравнение** — снимки сканирований и сравнение результатов.
- **Критичные узлы** — контроль важных хостов.
- **Очередь задач** — фоновые/очередные действия без блокировки UI.
- **Nmap-интеграция** — запуск Nmap из интерфейса с выбором флагов, скриптов NSE и пользовательских параметров.
- **Attack Surface / аудит** — анализ портов, рисков, признаков сервисов, отчёты.
- **Анализ трафика** — захват пакетов Scapy/Npcap, фильтрация, старт/стоп/очистка, CSV-экспорт.
- **Расширенный анализ трафика** — BPF-фильтр, PCAP-запись, top proto/port/top source, счётчик flows, предупреждение об аномалии доминирующего источника, колонка Info с DNS/HTTP признаками.
- **Углублённый статус устройства** — HTTP/TLS/SMB/SNMP признаки, filtered/no-response, camera/embedded hints, метод обнаружения.
- **Очистка данных** — кнопки очистки истории, инвентаря/журнала, мониторинга.
- **Экспорт** — CSV/TXT для мониторинга, аудита и трафика.

#### 3. Улучшения сканирования
- **TCP-fallback** при недостаточности ARP/ICMP:
  - `scan_range` — fallback обнаружения живых хостов;
  - `scan_network` — осторожный fallback для небольших подсетей (`<= /24`, порты `80/443/445/22`, timeout `0.35s`).
- Хосты, найденные по TCP, помечаются `discovery="tcp"`.
- Статусы портов: `open / closed / filtered-no-response`.
- Для TCP-хоста без MAC в UI показывается `неизвестен (TCP)`.
- Кэширование локальных сетей в `scan_range` / `is_target_fully_local`.

#### 4. Исправления и надёжность
- Исправлены регрессии после рефакторинга (`is_valid_target` вынесен в `ui/utils.py`).
- Точечное логирование `logger.debug(..., exc_info=True)` в ключевых `except Exception`.
- Для Windows subprocess добавлен `CREATE_NO_WINDOW`, чтобы уменьшить мелькание консольных окон.
- Исправлен экспорт CSV трафика: безопасные `src_label/dst_label`, поле `info`, обработка ошибок записи.
- Улучшена валидация целей (IP/CIDR/диапазон/hostname) в ключевых полях и профилях.
- Эвристики HTTP/TLS/SMB/SNMP/FILTERED помечены как признаки, требующие подтверждения.

#### 5. Технические изменения
- `core/version.py` — версия.
- `ui/workers.py` — QThread-воркеры.
- `ui/widgets.py` — общие виджеты.
- `ui/utils.py` — общая валидация.
- `scripts/smoke_check.py` — быстрая smoke-проверка.
- Удалены мёртвые импорты/неиспользуемые ассеты после проверки ссылок.
- Удалена неиспользуемая зависимость `requests` из `requirements.txt` и `pyproject.toml`.

### Проверки
- `python -m py_compile main.py ui/app.py ui/workers.py ui/widgets.py ui/utils.py core/scanner.py core/version.py scripts/smoke_check.py` — успешно.
- `scripts/smoke_check.py` — `smoke: ok`.

### Требует ручной проверки
- Полный GUI runtime.
- Реальная сеть, Npcap/Scapy, Nmap, права администратора.
- BPF/PCAP/DNS/HTTP признаки и экспорт трафика.
- TCP-fallback в реальных подсетях с ограниченным ARP/ICMP.
- Работа готового exe на чистой машине.

---

## EN — What Was Done and Updated

### Major Updates

#### 1. Rebranding and UI
- New name: **Eptal-Analyzer**.
- Dark gray modern UI, white text, rounded elements, clean buttons.
- Version moved to `core/version.py` (`v1.0.31`).
- Window title shows the version; top panel shows the app name.
- Splash screen credits L0p4Map and shows the current Eptal-Analyzer version.

#### 2. New Features
- **Network map** — device and connection visualization.
- **Network diagnostics** — adapter, Wi-Fi, DHCP/DNS, gateway, internet, MTU.
- **Ping / Traceroute / Port scan for any IP** — you can enter any IP address or host and run availability check (ping), route tracing (traceroute), and port/service scanning via Nmap.
- **Inventory and journal** — device records, appearance history, events/changes.
- **Scan history and comparison** — scan snapshots and result comparison.
- **Critical hosts** — tracking for important hosts.
- **Task queue** — background/queued actions without blocking the UI.
- **Nmap integration** — run Nmap from the UI with flags, NSE scripts, and custom arguments.
- **Attack Surface / audit** — ports, risks, service indicators, reports.
- **Traffic analysis** — Scapy/Npcap capture, filtering, start/stop/clear, CSV export.
- **Extended traffic analysis** — BPF filter, PCAP writing, top proto/port/top source, flow counter, dominant-source anomaly warning, Info column with DNS/HTTP indicators.
- **Deep device status** — HTTP/TLS/SMB/SNMP indicators, filtered/no-response, camera/embedded hints, discovery method.
- **Data clearing** — clear history, inventory/journal, monitoring data.
- **Exports** — CSV/TXT for monitoring, audit, and traffic.

#### 3. Scanning Improvements
- **TCP fallback** when ARP/ICMP is insufficient:
  - `scan_range` — live host fallback detection;
  - `scan_network` — cautious fallback for small subnets (`<= /24`, ports `80/443/445/22`, `0.35s` timeout).
- TCP-discovered hosts are marked as `discovery="tcp"`.
- Port states: `open / closed / filtered-no-response`.
- TCP hosts without MAC are shown as `unknown (TCP)` in UI.
- Local network caching in `scan_range` / `is_target_fully_local`.

#### 4. Fixes and Reliability
- Fixed refactoring regressions (`is_valid_target` moved to `ui/utils.py`).
- Added targeted `logger.debug(..., exc_info=True)` in key `except Exception` blocks.
- Added `CREATE_NO_WINDOW` for Windows subprocesses to reduce console flashing.
- Fixed traffic CSV export: safe `src_label/dst_label`, added `info`, write-error handling.
- Improved target validation (IP/CIDR/range/hostname) in key inputs and profiles.
- HTTP/TLS/SMB/SNMP/FILTERED heuristics are marked as indicators requiring confirmation.

#### 5. Technical Changes
- `core/version.py` — version.
- `ui/workers.py` — QThread workers.
- `ui/widgets.py` — shared widgets.
- `ui/utils.py` — shared validation.
- `scripts/smoke_check.py` — quick smoke check.
- Removed dead imports/unused assets after reference checks.
- Removed unused `requests` dependency from `requirements.txt` and `pyproject.toml`.

### Checks Performed
- `python -m py_compile main.py ui/app.py ui/workers.py ui/widgets.py ui/utils.py core/scanner.py core/version.py scripts/smoke_check.py` — passed.
- `scripts/smoke_check.py` — `smoke: ok`.

### Manual Runtime Testing Still Needed
- Full GUI runtime.
- Real network, Npcap/Scapy, Nmap, Administrator privileges.
- BPF/PCAP/DNS/HTTP indicators and traffic export.
- TCP fallback on real networks with restricted ARP/ICMP.
- Ready exe behavior on a clean machine.

---

## Attribution / License

- Original project: **L0p4Map** by L0p4.
- Fork/enhancements: **Eptal-Analyzer**.
- License: **GNU GPL v3.0 or later**.
