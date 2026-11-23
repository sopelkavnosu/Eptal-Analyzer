# Eptal-Analyzer

**Eptal-Analyzer** is a fork of [L0p4Map](https://github.com/L0p4/L0p4Map), developed as a separate Windows application for network analysis, diagnostics, and inventory.

The project keeps the original L0p4Map idea as its base, but introduces a new identity, redesigned UI, expanded functionality, fixes, and reliability improvements.  
Attribution to the original author and the **GNU General Public License v3.0 (GPL-3.0)** license are preserved (see `LICENSE`).

[Русская версия](README.md)

---

## What Was Done and Updated

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

## GPL-3.0 license

- Original project: **L0p4Map** by L0p4.
- Fork/enhancements: **Eptal-Analyzer**.
- License: **GNU General Public License v3.0 (GPL-3.0)**.
