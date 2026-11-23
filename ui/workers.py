"""Фоновые воркеры приложения."""

import json
import logging
import os
import re
import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

from PyQt6.QtCore import QThread, pyqtSignal
from scapy.all import ICMP, TCP, UDP, sniff, Raw
from scapy.all import IP as ScapyIP
try:
    from scapy.all import DNS, DNSQR
except Exception:
    DNS = DNSQR = None

from core.scanner import scan_network, scan_range

def _tcp_probe_host(host, port, timeout=1.5):
    # Быстрая TCP-проверка доступности порта.
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        logging.getLogger(__name__).debug("TCP probe failed", exc_info=True)
        return False


def decode_process_line(raw: bytes) -> str:
    # Декодирование вывода консольных команд с fallback для Windows.
    for enc in ("utf-8", "cp866", "cp1251"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


class GatewayCheckWorker(QThread):
    # Фоновая проверка доступности шлюза.
    result = pyqtSignal(str, bool, str)

    def __init__(self, gateway: str):
        super().__init__()
        self.gateway = gateway

    def run(self):
        ok = False
        detail = "ping"
        try:
            proc = subprocess.run(
                ["ping", "-n", "1", "-w", "1500", self.gateway],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            ok = proc.returncode == 0
        except Exception:
            logging.getLogger(__name__).debug("Gateway ping failed", exc_info=True)
            ok = False
        if not ok:
            # Дополнительная проверка: TCP-порт, чтобы отличить блокировку ICMP от недоступности.
            if _tcp_probe_host(self.gateway, 80) or _tcp_probe_host(self.gateway, 443) or _tcp_probe_host(self.gateway, 53):
                detail = "ping недоступен, но TCP-порт отвечает (возможна блокировка ICMP)"
                ok = True
            else:
                dns_ok = False
                try:
                    socket.gethostbyname("dns.google")
                    dns_ok = True
                except Exception:
                    dns_ok = False
                detail = "нет ответа на ping/TCP-порты 53,80,443"
                if not dns_ok:
                    detail += "; DNS недоступен (возможна проблема сети)"
        self.result.emit(self.gateway, ok, detail)


class CriticalHostsWorker(QThread):
    # Фоновая проверка доступности критичных узлов.
    result = pyqtSignal(dict)

    def __init__(self, hosts: list[str]):
        super().__init__()
        self.hosts = hosts

    def run(self):
        results = {}
        for host in self.hosts:
            ok = False
            detail = "нет ответа на ping"
            try:
                proc = subprocess.run(
                    ["ping", "-n", "1", "-w", "1500", host],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                ok = proc.returncode == 0
            except Exception:
                ok = False
            if ok:
                detail = "ping ok"
            elif _tcp_probe_host(host, 80) or _tcp_probe_host(host, 443):
                ok = True
                detail = "ping недоступен, TCP 80/443 отвечает"
            results[host] = {"ok": ok, "detail": detail}
        self.result.emit(results)


class DiagnosticsWorker(QThread):
    # Сбор диагностической информации о сети/адаптере.
    finished = pyqtSignal(dict)

    def run(self):
        data = {
            "adapter": {},
            "wifi": {},
            "checks": {},
            "error": "",
        }
        try:
            data["adapter"] = self._collect_adapter()
        except Exception as e:
            logging.getLogger(__name__).debug("Diagnostics: adapter collection failed", exc_info=True)
            data["error"] = str(e)
        try:
            data["wifi"] = self._collect_wifi()
        except Exception:
            logging.getLogger(__name__).debug("Diagnostics: wifi collection failed", exc_info=True)
            data["wifi"] = {}
        try:
            data["checks"] = self._collect_checks(data.get("adapter", {}))
        except Exception:
            logging.getLogger(__name__).debug("Diagnostics: checks collection failed", exc_info=True)
            data["checks"] = {}
        self.finished.emit(data)

    def _run_ps(self, script):
        # Выполнение PowerShell-команды и возврат текста.
        try:
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return proc.stdout.strip()
        except Exception:
            logging.getLogger(__name__).debug("PowerShell command failed", exc_info=True)
            return ""

    def _collect_adapter(self):
        info = {}
        try:
            ifaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            gw = get_default_gateway()
            # Выбираем активный интерфейс с IPv4.
            chosen = None
            for name, addrs in ifaces.items():
                st = stats.get(name)
                if not st or not st.isup or name.lower().startswith("loopback"):
                    continue
                ipv4 = [a for a in addrs if a.family == socket.AF_INET]
                if ipv4 and not ipv4[0].address.startswith("127."):
                    chosen = (name, ipv4[0], st)
                    break
            if chosen:
                name, addr, st = chosen
                info["name"] = name
                info["ip"] = addr.address
                info["mask"] = addr.netmask
                info["speed_mbps"] = getattr(st, "speed", None)
                info["mtu"] = getattr(st, "mtu", None)
                info["isup"] = st.isup
            info["gateway"] = gw or ""
        except Exception:
            logging.getLogger(__name__).debug("Diagnostics: failed to collect adapter info", exc_info=True)
        # DHCP/DNS через PowerShell.
        ps = self._run_ps(
            "Get-NetIPConfiguration | Select-Object -First 1 | ConvertTo-Json -Depth 4"
        )
        if ps:
            try:
                obj = json.loads(ps)
                if isinstance(obj, list):
                    obj = obj[0] if obj else {}
                dns = obj.get("DNSServer") or []
                dns_addrs = []
                if isinstance(dns, list):
                    for d in dns:
                        if isinstance(d, dict):
                            a = d.get("ServerAddresses") or []
                            if isinstance(a, list):
                                dns_addrs.extend([str(x) for x in a])
                            elif a:
                                dns_addrs.append(str(a))
                        else:
                            dns_addrs.append(str(d))
                elif isinstance(dns, dict):
                    a = dns.get("ServerAddresses") or []
                    dns_addrs.extend([str(x) for x in a] if isinstance(a, list) else [str(a)])
                info["dns"] = dns_addrs
                iface = obj.get("NetIPv4Interface") or {}
                info["dhcp"] = iface.get("Dhcp")
                if not info.get("gateway"):
                    ipv4gw = obj.get("IPv4DefaultGateway") or {}
                    info["gateway"] = ipv4gw.get("NextHop", "") or info.get("gateway", "")
                if not info.get("name"):
                    info["name"] = (obj.get("InterfaceAlias") or "")
            except Exception:
                logging.getLogger(__name__).debug("Failed to parse adapter PowerShell details", exc_info=True)
        # MTU fallback через netsh.
        if not info.get("mtu") and info.get("name"):
            out = self._run_ps(f"netsh interface ipv4 show subinterfaces \"{info['name']}\"")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    try:
                        info["mtu"] = int(parts[0])
                        break
                    except Exception:
                        logging.getLogger(__name__).debug("Failed to parse netsh MTU", exc_info=True)
        return info

    def _collect_wifi(self):
        out = self._run_ps("netsh wlan show interfaces")
        if not out or "SSID" not in out:
            return {}
        wifi = {}
        for raw in out.splitlines():
            if ":" not in raw:
                continue
            k, v = raw.split(":", 1)
            k = k.strip().lower()
            v = v.strip()
            if k == "ssid" and "bssid" not in k:
                wifi["ssid"] = v
            elif k == "bssid":
                wifi["bssid"] = v
            elif k in ("signal", "сигнал"):
                wifi["signal"] = v
            elif k in ("radio type", "тип радио"):
                wifi["radio"] = v
            elif k in ("authentication", "проверка подлинности"):
                wifi["auth"] = v
            elif k in ("cipher", "шифр"):
                wifi["cipher"] = v
            elif k in ("channel", "канал"):
                wifi["channel"] = v
            elif k in ("state", "состояние"):
                wifi["state"] = v
            elif k in ("receive rate (mbps)", "скорость приема (мбит/с)"):
                wifi["rx"] = v
            elif k in ("transmit rate (mbps)", "скорость передачи (мбит/с)"):
                wifi["tx"] = v
        # Определение "открытая/закрытая" по аутентификации.
        auth = (wifi.get("auth") or "").lower()
        if auth:
            wifi["open_network"] = "open" in auth or "открыт" in auth
        return wifi

    def _collect_checks(self, adapter):
        checks = {}
        gw = adapter.get("gateway") or get_default_gateway()
        checks["gateway"] = gw or ""
        checks["gateway_ok"] = False
        checks["dns_ok"] = False
        checks["internet_ok"] = False
        # Шлюз
        if gw:
            try:
                proc = subprocess.run(["ping", "-n", "1", "-w", "1500", gw], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                checks["gateway_ok"] = proc.returncode == 0
            except Exception:
                logging.getLogger(__name__).debug("Gateway check failed", exc_info=True)
                checks["gateway_ok"] = False
        # DNS
        try:
            socket.gethostbyname("dns.google")
            checks["dns_ok"] = True
        except Exception:
            logging.getLogger(__name__).debug("DNS check failed", exc_info=True)
            checks["dns_ok"] = False
        # Интернет (TCP 443)
        for host in ["1.1.1.1", "8.8.8.8"]:
            try:
                with socket.create_connection((host, 443), timeout=2):
                    checks["internet_ok"] = True
                    break
            except Exception:
                logging.getLogger(__name__).debug("Internet TCP check failed", exc_info=True)
        return checks


class ActionWorker(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, cmd: list):
        super().__init__()
        self.cmd = cmd
        self.process = None
        self._stop_requested = False

    def stop(self):
        # Корректная остановка дочернего процесса.
        self._stop_requested = True
        proc = self.process
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                logging.getLogger(__name__).debug("Failed to kill process", exc_info=True)

    def _decode_line(self, raw: bytes) -> str:
        # Декодирование вывода команды.
        return decode_process_line(raw)

    def run(self):
        try:
            self.process = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            self.output.emit(f"// error: command not found: {self.cmd[0]}")
            self.finished.emit()
            return
        except Exception as e:
            logging.getLogger(__name__).debug("ActionWorker failed to start", exc_info=True)
            self.output.emit(f"// error: {e}")
            self.finished.emit()
            return

        try:
            for raw in self.process.stdout:
                self.output.emit(self._decode_line(raw).rstrip("\r\n"))
        except Exception as e:
            if not self._stop_requested:
                logging.getLogger(__name__).debug("ActionWorker read failed", exc_info=True)
                self.output.emit(f"// error: {e}")
        try:
            self.process.wait(timeout=5)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                logging.getLogger(__name__).debug("Failed to kill ActionWorker process", exc_info=True)
        if not self._stop_requested and self.process.returncode not in (0, None):
            self.output.emit(f"// exit code: {self.process.returncode}")
        self.finished.emit()


class ScanWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, subnet):
        super().__init__()
        self.subnet = subnet

    def run(self):
        try:
            hosts = scan_network(self.subnet)
        except Exception:
            logging.getLogger(__name__).exception("ScanWorker failed")
            hosts = []
        self.finished.emit(hosts)


class RangeScanWorker(QThread):
    finished = pyqtSignal(list)

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        try:
            hosts = scan_range(self.target)
        except Exception:
            logging.getLogger(__name__).exception("RangeScanWorker failed")
            hosts = []
        self.finished.emit(hosts)


class TrafficWorker(QThread):
    packet_captured = pyqtSignal(dict)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, iface: str, bpf: str = "ip", pcap_path: str | None = None):
        super().__init__()
        self.iface = iface
        self.bpf = (bpf or "ip").strip() or "ip"
        self.pcap_path = pcap_path
        self._running = True

    def stop(self):
        self._running = False

    def run(self):
        writer = None
        try:
            if self.pcap_path:
                from scapy.utils import PcapWriter
                writer = PcapWriter(self.pcap_path, append=False, sync=True)
        except Exception as e:
            self.error.emit(f"PCAP: {e}")
            writer = None

        def process(pkt):
            if not self._running:
                return
            if ScapyIP not in pkt:
                return
            if writer is not None:
                try:
                    writer.write(pkt)
                except Exception:
                    logging.getLogger(__name__).debug("Failed to write PCAP packet", exc_info=True)

            src = pkt[ScapyIP].src
            dst = pkt[ScapyIP].dst
            size = len(pkt)
            proto = "OTHER"
            port = "-"
            info = ""

            if TCP in pkt:
                proto = "TCP"
                port = str(pkt[TCP].dport)
                # Простое извлечение HTTP Host/запроса из payload (признак, без полного парсинга).
                try:
                    if pkt.haslayer(Raw):
                        raw = bytes(pkt[Raw].load[:512])
                        text = raw.decode("utf-8", errors="ignore")
                        if text.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/")):
                            first = text.split("\r\n", 1)[0][:120]
                            host = ""
                            for line in text.split("\r\n")[1:8]:
                                if line.lower().startswith("host:"):
                                    host = line.split(":", 1)[1].strip()[:80]
                                    break
                            info = f"HTTP {first}" + (f" host={host}" if host else "")
                except Exception:
                    pass
            elif UDP in pkt:
                proto = "UDP"
                port = str(pkt[UDP].dport)
                # DNS-запрос (признак).
                try:
                    if DNS is not None and pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt[DNS].qdcount > 0 and pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore")
                        info = f"DNS {str(qname).strip('.')[:120]}"
                except Exception:
                    pass
            elif ICMP in pkt:
                proto = "ICMP"

            self.packet_captured.emit({
                "src": src,
                "dst": dst,
                "proto": proto,
                "port": port,
                "size": size,
                "info": info[:160],
            })

        try:
            sniff(
                iface=self.iface,
                prn=process,
                store=False,
                filter=self.bpf,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            self.error.emit(str(e))
        finally:
            try:
                if writer is not None:
                    writer.close()
            except Exception:
                logging.getLogger(__name__).debug("Failed to close PCAP writer", exc_info=True)
        self.finished.emit()

CVSS_MIN = 4.0
MAX_CVES_PER_PORT = 5
GENERIC_SERVICES = {"tcpwrapped", "unknown", "filtered", ""}
HIGH_RISK_PORTS  = {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}
MEDIUM_RISK_PORTS = {22,80,8080,3306,5432,1433,2375,2376,4444}

def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0: return "CRITICAL"
    if cvss >= 7.0: return "HIGH"
    if cvss >= 4.0: return "MEDIUM"
    return "LOW"


class AttackSurfaceWorker(QThread):
    finished = pyqtSignal(dict)
    status_update = pyqtSignal(str)
    port_found = pyqtSignal(dict)

    def __init__(self, target: str):
        super().__init__()
        self.target = target
        self.process = None
        self._stop_requested = False

    def stop(self):
        # Корректная остановка nmap-процесса.
        self._stop_requested = True
        proc = self.process
        if proc is None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                logging.getLogger(__name__).debug("Failed to kill process", exc_info=True)

    def _decode_line(self, raw: bytes) -> str:
        # Декодирование вывода команды.
        return decode_process_line(raw)

    def run(self):
        import tempfile, xml.etree.ElementTree as ET

        tmp = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
        tmp_path = tmp.name
        tmp.close()

        cmd = [
            "nmap", "-sV", "-O",
            "--script", "vulners",
            "--open", "-Pn", "-T4",
            "-oX", tmp_path,
            self.target
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            self.status_update.emit("// error: nmap not found. Install Nmap and add it to PATH.")
            self.finished.emit({"target": self.target, "os": "Unknown", "ports": [], "cves": []})
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return
        except Exception as e:
            self.status_update.emit(f"// error: {e}")
            self.finished.emit({"target": self.target, "os": "Unknown", "ports": [], "cves": []})
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            return

        seen_ports = set()

        try:
            for raw in self.process.stdout:
                line = self._decode_line(raw).strip()
                if not line:
                    continue

                if "Scanning" in line or "scan report" in line:
                    self.status_update.emit(f"// {line.lower()}")
                elif "OS details" in line or "Running:" in line:
                    self.status_update.emit(f"// {line.lower()}")
                elif "/tcp" in line or "/udp" in line:
                    self.status_update.emit(f"// port found: {line}")
                    match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
                    if match:
                        portid = match.group(1)
                        if portid in seen_ports:
                            continue
                        seen_ports.add(portid)
                        proto = match.group(2)
                        svc = match.group(3)
                        version = match.group(4).strip()
                        portnum = int(portid)
                        if portnum in {21,23,25,110,135,139,445,512,513,514,3389,5900,6379,27017}:
                            risk = "HIGH"
                        elif portnum in {22,80,8080,3306,5432,1433,2375,2376,4444}:
                            risk = "MEDIUM"
                        else:
                            risk = "LOW"
                        self.port_found.emit({
                            "port": portid, "protocol": proto,
                            "service": svc, "version": version or "-", "risk": risk,
                        })
        except Exception as e:
            if not self._stop_requested:
                logging.getLogger(__name__).debug("AttackSurfaceWorker read failed", exc_info=True)
                self.status_update.emit(f"// error: {e}")

        try:
            self.process.wait(timeout=5)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                logging.getLogger(__name__).debug("Failed to kill AttackSurfaceWorker process", exc_info=True)

        if self._stop_requested:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            self.status_update.emit("// interrupted")
            self.finished.emit({"target": self.target, "os": "Unknown", "ports": [], "cves": []})
            return

        self.status_update.emit("// parsing vulnerabilities...")

        result = self._parse(tmp_path)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        self.status_update.emit("// scan complete")
        self.finished.emit(result)

    def _parse(self, xml_path: str) -> dict:
        import xml.etree.ElementTree as ET
        from collections import defaultdict

        result = {
            "target": self.target,
            "os": "Unknown",
            "ports": [],
            "cves": [],
        }

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except (ET.ParseError, FileNotFoundError):
            return result

        host = root.find("host")
        if host is None:
            return result

        cpe_list = [cpe.text or "" for cpe in host.findall(".//cpe")]
        is_windows = any("windows" in c for c in cpe_list)
        is_linux   = any("linux"   in c for c in cpe_list)
        is_macos   = any("mac_os"  in c or "macos" in c for c in cpe_list)

        osmatch = host.find(".//osmatch")
        if osmatch is not None:
            os_name  = osmatch.get("name", "")
            accuracy = osmatch.get("accuracy", "?")
            result["os"] = f"{os_name} ({accuracy}%)"
            if not any([is_windows, is_linux, is_macos]):
                osL = os_name.lower()
                is_windows = "windows" in osL
                is_linux   = any(k in osL for k in ["linux","ubuntu","debian"])
                is_macos   = any(k in osL for k in ["mac os","macos","darwin"])

        port_cve_count = defaultdict(int)

        for port in host.findall(".//port"): 
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            portid   = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service  = port.find("service")

            svc_name    = service.get("name",    "-") if service is not None else "-"
            svc_product = service.get("product", "") if service is not None else ""
            svc_version = service.get("version", "") if service is not None else ""
            svc_full    = f"{svc_product} {svc_version}".strip() or "-"
            svc_ostype  = service.get("ostype",  "").lower() if service is not None else ""

            portnum = int(portid)
            if portnum in HIGH_RISK_PORTS:
                risk = "HIGH"
            elif portnum in MEDIUM_RISK_PORTS:
                risk = "MEDIUM"
            else:
                risk = "LOW"

            result["ports"].append({
                "port":     portid,
                "protocol": protocol,
                "service":  svc_name,
                "version":  svc_full,
                "risk":     risk,
            })

            for script in port.findall("script"):
                scriptID = script.get("id", "")
                output   = script.get("output", "")

                if not any(x in scriptID for x in ["vulners", "vuln", "exploit"]):
                    continue

                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue

                    match = re.match(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)\s+https?://", line)
                    if not match:
                        continue

                    cve_id = match.group(1)
                    cvss   = float(match.group(2))

                    if cvss < CVSS_MIN:
                        continue

                    if svc_name.lower() in GENERIC_SERVICES:
                        continue

                    if not svc_product:
                        continue

                    if any(c["id"] == cve_id for c in result["cves"]):
                        continue

                    if port_cve_count[portid] >= MAX_CVES_PER_PORT:
                        continue

                    windows_only = {"netlogon", "msrpc", "microsoft-ds", "ms-wbt-server"}
                    if svc_name.lower() in windows_only and not is_windows:
                        continue

                    if svc_ostype:
                        if "windows" in svc_ostype and not is_windows:
                            continue
                        if "linux" in svc_ostype and not is_linux:
                            continue

                    port_cve_count[portid] += 1
                    result["cves"].append({
                        "id":      cve_id,
                        "cvss":    cvss,
                        "port":    portid,
                        "service": svc_name,
                        "detail":  f"{svc_name} {svc_full} — {cve_id}",
                    })

        result["cves"].sort(key=lambda c: c["cvss"], reverse=True)

        for port_entry in result["ports"]:
            port_cves = [c for c in result["cves"] if c["port"] == port_entry["port"]]
            if not port_cves:
                continue
            max_cvss = max(c["cvss"] for c in port_cves)
            port_entry["risk"] = cvss_to_severity(max_cvss)

        return result


