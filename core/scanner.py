import csv as _csv
import ipaddress
import logging
import os
import re
import socket
import ssl
import subprocess
import threading
import time

logger = logging.getLogger(__name__)
from concurrent.futures import ThreadPoolExecutor, as_completed

import psutil
from scapy.all import ARP, ICMP, Ether, conf, sr1, srp
from scapy.all import IP as ScapyIP

_vendor_cache: dict[str, str] = {}
_oui_db: dict[str, str] = {}

TOPOLOGY_PROBE_PORTS = [80, 443, 22, 23, 53, 8080, 8443, 179, 161, 8291, 2601, 4786]

NETWORK_DEVICE_VENDORS = [
    "cisco",
    "mikrotik",
    "ubiquiti",
    "juniper",
    "fortinet",
    "palo alto",
    "aruba",
    "ruckus",
    "meraki",
    "extreme",
    "brocade",
    "h3c",
    "huawei",
    "zyxel",
    "dlink",
    "tp-link",
    "netgear",
    "linksys",
    "tenda",
    "openwrt",
    "dd-wrt",
    "edgecore",
    "cambium",
    "aerohive",
]

PC_VENDORS = [
    "intel",
    "dell",
    "lenovo",
    "hp",
    "hewlett",
    "acer",
    "gigabyte",
    "msi",
    "asrock",
    "asus",
    "supermicro",
    "fujitsu",
]

MOBILE_VENDORS = [
    "samsung",
    "xiaomi",
    "oneplus",
    "oppo",
    "realme",
    "motorola",
    "lg electronics",
    "sony mobile",
    "zte",
]


class ContinuousMonitor:
    def __init__(self):
        self._running = False
        self._thread = None
        self._callback = None
        self._interval = 60
        self._last_hosts = []
        self._lock = threading.Lock()
        self._iface = None
        self._subnet = None

    def start(self, subnet: str, iface: str = None, interval: int = 60, callback=None):
        self._running = True
        self._interval = interval
        self._callback = callback
        self._iface = iface
        self._subnet = subnet
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def get_last_hosts(self):
        with self._lock:
            return list(self._last_hosts)

    def _monitor_loop(self):
        while self._running:
            try:
                hosts = scan_network(self._subnet)
                with self._lock:
                    self._last_hosts = hosts
                if self._callback:
                    self._callback(hosts)
            except Exception:
                logger.debug("ContinuousMonitor iteration failed", exc_info=True)
            for _ in range(self._interval):
                if not self._running:
                    break
                time.sleep(1)


def _load_oui_db():
    global _oui_db
    if _oui_db:
        return
    db_path = os.path.join(os.path.dirname(__file__), "oui.csv")
    if not os.path.exists(db_path):
        return
    with open(db_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = _csv.DictReader(f)
        for row in reader:
            oui = row.get("Assignment", "").upper().strip()
            name = row.get("Organization Name", "").strip()
            if oui and name:
                _oui_db[oui] = name


def get_network_interfaces():
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for iface, addr_list in addrs.items():
        if iface == "lo" or iface not in stats or not stats[iface].isup:
            continue
        ip = ""
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
        if ip.startswith("127."):
            continue
        interfaces.append({"name": iface, "ip": ip})

    return interfaces


def get_local_subnet(iface_name=None) -> str:
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    if iface_name:
        if iface_name not in interfaces:
            raise RuntimeError(f"Interface '{iface_name}' not found.")
        if not stats[iface_name].isup:
            raise RuntimeError(f"Interface '{iface_name}' not active.")
        for addr in interfaces[iface_name]:
            if addr.family == socket.AF_INET:
                return str(
                    ipaddress.IPv4Network(
                        f"{addr.address}/{addr.netmask}", strict=False
                    )
                )
        raise RuntimeError(f"No IPv4 address on '{iface_name}'.")
    for nome, indirizzi in interfaces.items():
        if not stats[nome].isup:
            continue
        for addr in indirizzi:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("127."):
                    continue
                return str(ipaddress.IPv4Network(f"{ip}/{addr.netmask}", strict=False))
    raise RuntimeError("No active interface found.")


def get_default_gateway() -> str | None:
    # Получение шлюза по умолчанию в Windows.
    try:
        out = subprocess.check_output(
            ["route", "print", "0.0.0.0"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        logger.debug("get_default_gateway: route print failed", exc_info=True)
    try:
        out = subprocess.check_output(
            ["powershell", "-Command", "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        gw = out.strip()
        if gw:
            return gw
    except Exception:
        logger.debug("get_default_gateway: PowerShell fallback failed", exc_info=True)
    return None


def get_vendor(mac: str) -> str:
    global _vendor_cache
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    if oui in _vendor_cache:
        return _vendor_cache[oui]
    _load_oui_db()
    if oui in _oui_db:
        vendor = _oui_db[oui]
        _vendor_cache[oui] = vendor
        return vendor
    _vendor_cache[oui] = "Unknown"
    return "Unknown"


def _dns_hostname(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
        if name and name != ip:
            return name
    except socket.herror:
        pass
    return None


def _netbios_hostname(ip: str) -> str | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            b"\x00\x00!\x00\x01"
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 72:
            name = data[57:72].decode("ascii", errors="ignore").strip()
            name = "".join(c for c in name if c.isprintable()).strip()
            if name:
                return name
    except Exception:
        logger.debug("_netbios_hostname failed for %s", ip, exc_info=True)
    return None


def resolve_hostname(ip: str) -> str:
    name = _dns_hostname(ip)
    if name:
        return name
    name = _netbios_hostname(ip)
    if name:
        return name
    return ip


def _probe_ttl(ip: str) -> int | None:
    try:
        pkt = ScapyIP(dst=ip, ttl=64) / ICMP()
        reply = sr1(pkt, timeout=1, verbose=False)
        if reply and ICMP in reply:
            return reply[ScapyIP].ttl
    except Exception:
        logger.debug("_probe_ttl failed for %s", ip, exc_info=True)
    return None


def _ttl_to_os_hint(ttl: int | None) -> str:
    if ttl is None:
        return "unknown"
    if ttl <= 64:
        return "linux/macos"
    if ttl <= 128:
        return "windows"
    return "network_device"


def _probe_port_states(ip: str, ports: list[int], timeout: float = 0.5) -> tuple[list[int], list[int], list[int]]:
    # Проверка портов: открытые, отфильтрованные (таймаут/no-response), закрытые (refused).
    open_ports = []
    filtered_ports = []
    closed_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append(port)
            elif result in (10061, 111, 61):  # connection refused - хост отвечает, порт закрыт
                closed_ports.append(port)
            elif result in (10060, 110, 11, 10035):  # timeout/no-response - вероятно filtered
                filtered_ports.append(port)
            else:
                filtered_ports.append(port)
        except socket.timeout:
            filtered_ports.append(port)
        except Exception:
            logger.debug("_probe_port_states failed for %s:%s", ip, port, exc_info=True)
    return open_ports, filtered_ports, closed_ports


def _probe_open_ports(ip: str, ports: list[int], timeout: float = 0.5) -> list[int]:
    open_ports, _, _ = _probe_port_states(ip, ports, timeout=timeout)
    return open_ports


def _infer_role(
    ip: str,
    vendor: str,
    hostname: str,
    ttl: int | None,
    open_ports: list[int],
    is_gateway: bool,
) -> str:
    v = vendor.lower()
    h = hostname.lower()
    os_hint = _ttl_to_os_hint(ttl)

    if is_gateway:
        return "gateway"

    if h in ("router", "gateway", "_gateway", "default-gateway"):
        return "gateway"

    if any(
        k in v
        for k in [
            "cisco",
            "mikrotik",
            "ubiquiti",
            "juniper",
            "fortinet",
            "edgecore",
            "brocade",
            "h3c",
        ]
    ):
        if any(p in open_ports for p in [22, 23, 179, 8291, 2601, 4786]):
            return "router"
        return "router"

    if any(
        k in v
        for k in [
            "tp-link",
            "netgear",
            "dlink",
            "linksys",
            "tenda",
            "zyxel",
            "aruba",
            "ruckus",
            "meraki",
            "cambium",
            "aerohive",
            "ubiquiti",
        ]
    ):
        if any(p in open_ports for p in [80, 443, 8080, 8443]):
            return "ap"
        return "ap"

    if any(
        k in h
        for k in [
            "router",
            "gw",
            "gateway",
            "firewall",
            "pfsense",
            "opnsense",
            "vyos",
            "mikrotik",
        ]
    ):
        return "router"

    if any(
        k in h
        for k in [
            "ap",
            "wifi",
            "wlan",
            "wireless",
            "access-point",
            "access_point",
            "hotspot",
            "ssid",
        ]
    ):
        return "ap"

    if any(k in h for k in ["switch", "sw-", "sw_", "core-sw", "dist-sw"]):
        return "switch"

    if any(k in v for k in ["raspberry"]) or "raspberry" in h:
        return "raspberry"

    if any(k in v for k in ["vmware", "virtualbox", "proxmox", "parallels"]):
        return "vm"

    if any(k in v for k in ["apple"]) or any(
        k in h for k in ["iphone", "ipad", "macbook", "imac", "apple"]
    ):
        return "apple"

    if any(
        k in v
        for k in [
            "samsung",
            "xiaomi",
            "oneplus",
            "oppo",
            "realme",
            "motorola",
            "lg electronics",
            "sony mobile",
            "zte",
            "huawei",
            "honor",
            "google",
        ]
    ):
        return "mobile"
    if any(k in h for k in ["android", "iphone", "phone", "mobile", "tablet", "ipad", "galaxy", "pixel"]):
        return "mobile"

    if os_hint == "network_device":
        if any(p in open_ports for p in [80, 443, 8080]):
            return "ap"
        return "router"

    if any(k in v for k in PC_VENDORS):
        return "pc"
    if any(
        k in h
        for k in [
            "desktop",
            "pc-",
            "-pc",
            "workstation",
            "laptop",
            "linux",
            "windows",
            "ubuntu",
            "debian",
            "fedora",
        ]
    ):
        return "pc"

    if os_hint == "linux/macos" and 22 in open_ports:
        return "pc"

    if os_hint == "windows" and any(p in open_ports for p in [135, 139, 445]):
        return "pc"

    return "unknown"


def _probe_snmp_sysdescr(ip: str) -> str | None:
    try:
        community = b"public"
        oid = b"\x2b\x06\x01\x02\x01\x01\x01\x00"
        request = (
            b"\x30\x29"
            b"\x02\x01\x00"
            b"\x04" + bytes([len(community)]) + community + b"\xa0\x1c"
            b"\x02\x04\x00\x00\x00\x01"
            b"\x02\x01\x00"
            b"\x02\x01\x00"
            b"\x30\x0e"
            b"\x30\x0c"
            b"\x06\x08" + oid + b"\x05\x00"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(request, (ip, 161))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if data and len(data) > 30:
            payload = data[30:]
            try:
                return payload.decode("ascii", errors="ignore").strip()
            except Exception:
                logger.debug("_probe_snmp_sysdescr decode failed for %s", ip, exc_info=True)
    except Exception:
        logger.debug("_probe_snmp_sysdescr failed for %s", ip, exc_info=True)
    return None


def _enrich_host(host: dict, known_gateway_ip: str | None) -> dict:
    ip = host["ip"]
    host["hostname"] = resolve_hostname(ip)
    host["vendor"] = get_vendor(host["mac"])

    ttl = _probe_ttl(ip)
    host["ttl"] = ttl
    host["os_hint"] = _ttl_to_os_hint(ttl)

    open_ports, filtered_ports, closed_ports = _probe_port_states(ip, TOPOLOGY_PROBE_PORTS, timeout=0.4)
    host["open_ports"] = open_ports
    host["filtered_ports"] = filtered_ports
    host["closed_ports"] = closed_ports
    host["embedded_device"] = fingerprint_embedded_device(ip, open_ports) if open_ports else ""

    snmp_desc = None
    if 161 in open_ports or ttl is None or (ttl is not None and ttl > 128):
        snmp_desc = _probe_snmp_sysdescr(ip)
    host["snmp_desc"] = snmp_desc or ""

    # Дополнительная информация по устройству.
    host["http_title"] = _probe_http_title(ip, open_ports)
    host["tls_cert"] = _probe_tls_cert(ip, open_ports)
    host["smb_info"] = _probe_smb_info(ip, open_ports)
    host["camera_hint"] = _detect_camera_hint(ip, host["vendor"], host["hostname"], open_ports, host["http_title"])

    vendor_for_role = host["vendor"]
    if snmp_desc:
        vendor_for_role = snmp_desc + " " + vendor_for_role

    is_gw = ip == known_gateway_ip
    host["role"] = _infer_role(
        ip,
        vendor_for_role,
        host["hostname"],
        ttl,
        open_ports,
        is_gw,
    )

    return host


def scan_network(subnet: str) -> list[dict]:
    conf.verb = 0

    known_gateway = get_default_gateway()

    pacchetto = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    risposte, _ = srp(pacchetto, timeout=2, retry=2, inter=0.01, verbose=False)

    seen_macs: dict[str, str] = {}
    for _, risposta in risposte:
        mac = risposta[Ether].src
        ip = risposta[ARP].psrc
        if mac not in seen_macs:
            seen_macs[mac] = ip

    if known_gateway and known_gateway not in seen_macs.values():
        gw_mac = _arp_resolve_mac(known_gateway)
        if gw_mac:
            seen_macs[gw_mac] = known_gateway

    # Осторожный TCP-fallback для хостов, не ответивших на ARP (только небольшие подсети).
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
        known_ips = set(seen_macs.values())
        if net.num_addresses <= 256:
            candidates = [str(ip) for ip in net.hosts() if str(ip) not in known_ips]
            def _probe_tcp(ip):
                if _tcp_ping(ip, ports=(80, 443, 445, 22), timeout=0.35):
                    return ip
                return None
            with ThreadPoolExecutor(max_workers=32) as ex:
                for future in as_completed([ex.submit(_probe_tcp, ip) for ip in candidates]):
                    found = future.result()
                    if found:
                        # MAC неизвестен, но хост отвечает по TCP - добавляем как признак.
                        seen_macs[f"tcp:{found}"] = found
    except Exception:
        logger.debug("scan_network TCP fallback failed", exc_info=True)

    hosts = []
    for mac, ip in seen_macs.items():
        is_tcp = isinstance(mac, str) and mac.startswith("tcp:")
        hosts.append(
            {
                "ip": ip,
                "mac": "" if is_tcp else mac,
                "hostname": ip,
                "vendor": "" if is_tcp else "...",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "filtered_ports": [],
                "closed_ports": [],
                "role": "unknown",
                "snmp_desc": "",
                "http_title": "",
                "tls_cert": "",
                "smb_info": "",
                "camera_hint": "",
                "embedded_device": "",
                "discovery": "tcp" if is_tcp else "arp",
            }
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(_enrich_host, host, known_gateway): host for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                logger.debug("Host enrichment failed", exc_info=True)
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results


def _arp_resolve_mac(ip: str) -> str | None:
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(pkt, timeout=1, retry=1, verbose=False)
        for _, reply in ans:
            return reply[Ether].src
    except Exception:
        logger.debug("_arp_resolve_mac failed for %s", ip, exc_info=True)


EMBEDDED_DEVICE_SIGNATURES = {
    "hp ilo": ["integrated lights-out", "ilo standard", "hp ilo"],
    "infoprint": ["infoprint", "ricoh infoprint"],
    "lantronix xport": ["xport", "lantronix"],
    "sato printer": ["sato", "nicelabel sato"],
    "zebra printer": ["zebra technologies", "zebra printer", "zpl"],
}


def _grab_http_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        data = b""
        while len(data) < 4096:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        return data.decode("latin-1", errors="ignore")
    except Exception:
        logger.debug("_grab_http_banner failed for %s:%s", ip, port, exc_info=True)
        return ""


def _extract_http_title(banner: str) -> str:
    # Извлечение заголовка HTML-страницы из HTTP-ответа.
    m = re.search(r"<title[^>]*>(.*?)</title>", banner, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:120]


def _probe_http_title(ip: str, open_ports: list[int]) -> str:
    for port in (p for p in (80, 8080, 8000, 8888, 443, 8443) if p in open_ports):
        banner = _grab_http_banner(ip, port)
        title = _extract_http_title(banner)
        if title:
            return title
    return ""


def _probe_tls_cert(ip: str, open_ports: list[int]) -> str:
    # Получение краткой информации о TLS-сертификате.
    for port in (p for p in (443, 8443) if p in open_ports):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            cn = ""
            # Простой поиск CN (OID 2.5.4.3) в DER.
            oid = b"\x06\x03\x55\x04\x03"
            idx = der.find(oid)
            if idx != -1:
                rest = der[idx + len(oid):]
                if len(rest) >= 2:
                    # Пропускаем тип строки и длину.
                    t = rest[0]
                    l = rest[1]
                    start = 2
                    if l & 0x80:
                        n = l & 0x7F
                        l = int.from_bytes(rest[2:2+n], "big")
                        start = 2 + n
                    cn = rest[start:start+l].decode("utf-8", errors="ignore").strip()
            return f"CN={cn}"[:160] if cn else "Сертификат получен"
        except Exception:
            logger.debug("_probe_tls_cert failed for %s:%s", ip, port, exc_info=True)
            continue
    return ""


def _probe_smb_info(ip: str, open_ports: list[int]) -> str:
    # Базовая проверка SMB: порт открыт и ответ на negotiate.
    if 445 not in open_ports and 139 not in open_ports:
        return ""
    try:
        with socket.create_connection((ip, 445), timeout=1.5) as sock:
            # Минимальный SMB2 negotiate request.
            pkt = bytes.fromhex(
                "00000054fe534d424000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ) + b"\x00" * 4
            sock.sendall(pkt)
            data = sock.recv(4)
            if data:
                return "SMB порт открыт (445)"
    except Exception:
        logger.debug("_probe_smb_info failed for %s", ip, exc_info=True)
    return "SMB порт открыт" if 445 in open_ports or 139 in open_ports else ""


def _detect_camera_hint(ip: str, vendor: str, hostname: str, open_ports: list[int], http_title: str) -> str:
    # Эвристика: возможно камера/видеоустройство.
    reasons = []
    v = (vendor or "").lower()
    h = (hostname or "").lower()
    t = (http_title or "").lower()
    cam_vendors = ["hikvision", "dahua", "axis", "hanwha", "uniview", "reolink", "tapo", "ezviz", "vivotek", "foscam", "amcrest"]
    if any(x in v for x in cam_vendors):
        reasons.append("vendor")
    if any(x in h for x in ["cam", "camera", "ipc", "dvr", "nvr"]):
        reasons.append("hostname")
    if any(x in t for x in ["camera", "ipcam", "webcam", "dvr", "nvr", "onvif"]):
        reasons.append("http title")
    cam_ports = {554, 8000, 8899, 37777, 34567}
    found_ports = sorted(set(open_ports) & cam_ports)
    if found_ports:
        reasons.append("ports:" + ",".join(map(str, found_ports)))
    if 554 in open_ports:
        reasons.append("RTSP")
    if not reasons:
        return ""
    return "Возможно камера (" + ", ".join(dict.fromkeys(reasons)) + ")"


def fingerprint_embedded_device(ip: str, open_ports: list[int]) -> str:
    for port in (p for p in (80, 443, 8080) if p in open_ports):
        banner = _grab_http_banner(ip, port).lower()
        if not banner:
            continue
        for device_name, signatures in EMBEDDED_DEVICE_SIGNATURES.items():
            if any(sig in banner for sig in signatures):
                return device_name
    return ""


def _local_networks() -> list[ipaddress.IPv4Network]:
    nets = []
    try:
        for _, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.netmask:
                    try:
                        nets.append(
                            ipaddress.IPv4Network(
                                f"{addr.address}/{addr.netmask}", strict=False
                            )
                        )
                    except Exception:
                        logger.debug("_local_networks: failed to parse interface address", exc_info=True)
    except Exception:
        logger.debug("_local_networks failed", exc_info=True)
    return nets


def _is_local_ip(ip: str, nets: list[ipaddress.IPv4Network] | None = None) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    nets = nets if nets is not None else _local_networks()
    return any(addr in net for net in nets)


def parse_target_range(target: str) -> list[str]:
    target = target.strip()
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if m:
        prefix, start, end = m.groups()
        start, end = int(start), int(end)
        if start > end:
            start, end = end, start
        return [f"{prefix}{i}" for i in range(start, end + 1)]
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        return [str(ip) for ip in ipaddress.ip_network(target, strict=False).hosts()]
    except ValueError:
        return []


def is_target_fully_local(target: str) -> bool:
    ips = parse_target_range(target)
    if not ips:
        return False
    nets = _local_networks()
    return all(_is_local_ip(ip, nets) for ip in ips)


def _traceroute_hops(ip: str, max_hops: int = 15, timeout: float = 0.8) -> list[str | None]:
    hops: list[str | None] = []
    for ttl in range(1, max_hops + 1):
        pkt = ScapyIP(dst=ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=False)
        if reply is None:
            hops.append(None)
            continue
        hops.append(reply.src)
        if reply.src == ip:
            break
    return hops


def _last_known_hop(hops: list[str | None]) -> str | None:
    for hop in reversed(hops):
        if hop:
            return hop
    return None


def _tcp_ping(ip: str, ports: tuple[int, ...] = (80, 443, 22, 445, 3389), timeout: float = 0.8) -> bool:
    # TCP-fallback: считаем хост вероятно доступным, если порт открыт/закрыт, но отвечает.
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                res = sock.connect_ex((ip, port))
                if res in (0, 10061, 111):  # открыт или активно отказал - хост отвечает
                    return True
        except Exception:
            continue
    return False


def scan_range(target: str) -> list[dict]:
    conf.verb = 0
    known_gateway = get_default_gateway()
    ip_list = parse_target_range(target)
    nets = _local_networks()

    def probe(ip: str) -> dict | None:
        if _is_local_ip(ip, nets):
            mac = _arp_resolve_mac(ip)
            if not mac:
                # Fallback: иногда ARP не проходит, но хост отвечает по TCP.
                if not _tcp_ping(ip):
                    return None
                return {"ip": ip, "mac": "", "router_hop": None, "discovery": "tcp"}
            return {"ip": ip, "mac": mac, "router_hop": None, "discovery": "arp"}

        alive = sr1(ScapyIP(dst=ip) / ICMP(), timeout=1.0, verbose=False)
        discovery = "icmp"
        if alive is None:
            # Fallback для хостов с блокировкой ICMP.
            if not _tcp_ping(ip):
                return None
            discovery = "tcp"

        hops = _traceroute_hops(ip)
        if hops and hops[-1] == ip:
            hop = _last_known_hop(hops[:-1]) or known_gateway
        else:
            hop = _last_known_hop(hops) or known_gateway
        return {"ip": ip, "mac": "", "router_hop": hop, "discovery": discovery}

    raw_hosts = []
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(probe, ip): ip for ip in ip_list}
        for future in as_completed(futures):
            result = future.result()
            if result:
                raw_hosts.append(result)

    hosts = []
    for raw in raw_hosts:
        hosts.append(
            {
                "ip": raw["ip"],
                "mac": raw["mac"],
                "hostname": raw["ip"],
                "vendor": "..." if raw["mac"] else "",
                "ttl": None,
                "os_hint": "unknown",
                "open_ports": [],
                "filtered_ports": [],
                "closed_ports": [],
                "role": "unknown",
                "snmp_desc": "",
                "embedded_device": "",
                "http_title": "",
                "tls_cert": "",
                "smb_info": "",
                "camera_hint": "",
                "router_hop": raw["router_hop"],
                "discovery": raw.get("discovery", ""),
            }
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {
            executor.submit(_enrich_host, host, known_gateway): host for host in hosts
        }
        results = []
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                logger.debug("Host enrichment failed", exc_info=True)
                results.append(futures[future])

    results.sort(key=lambda h: [int(x) for x in h["ip"].split(".")])
    return results
