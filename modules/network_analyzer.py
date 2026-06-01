"""
Network analysis and monitoring module
"""
# modules/network_analyzer.py

import psutil           # For network connections and traffic stats
import socket           # For IP/hostname resolution
import time             # For traffic rate calculations
from datetime import datetime  # For timestamps


# -------------------------------------------------------
# KNOWN MALICIOUS / SUSPICIOUS PORTS
# These ports are commonly used by malware, RATs,
# botnets, and unauthorized remote access tools.
# Legitimate software rarely uses these ports.
# -------------------------------------------------------

SUSPICIOUS_PORTS = {
    # Remote Access / RATs
    1080: "SOCKS Proxy / possible RAT tunnel",
    4444: "Metasploit default listener port",
    5555: "Android Debug Bridge / RAT",
    6666: "IRC botnet communication",
    6667: "IRC botnet communication",
    6668: "IRC botnet communication",
    6669: "IRC botnet communication",
    1234: "Common RAT/backdoor port",
    2222: "Unauthorized SSH / backdoor",
    7777: "Common backdoor port",
    8888: "Common backdoor / proxy port",
    9999: "Common backdoor port",
    31337: "Elite hacker / backdoor port (old but still used)",
    12345: "NetBus RAT",
    12346: "NetBus RAT",
    20034: "NetBus 2 RAT",
    27374: "SubSeven RAT",
    1243: "SubSeven RAT",

    # Trojans and botnets
    2745: "Bagle worm",
    3127: "MyDoom worm",
    3128: "Common open proxy",
    6129: "DameWare remote access",
    65000: "Stacheldraht DDoS tool",
    60000: "Deep Throat RAT",
    54321: "Back Orifice 2000",
    1337: "Common hacker/backdoor port",

    # Data exfiltration
    25: "SMTP — watch for unauthorized email sending",
    587: "SMTP submission — watch for spam bots",
}

# -------------------------------------------------------
# SUSPICIOUS IP RANGES
# These are private/reserved ranges that should never
# appear as REMOTE addresses. If your machine is
# connecting outbound to these, something is wrong.
# Also includes known bad IP blocks.
# -------------------------------------------------------

SUSPICIOUS_IP_PREFIXES = [
    "0.",           # Reserved
    "169.254.",     # APIPA — should never be a remote address
    "224.",         # Multicast — unusual for direct connections
    "225.", "226.", "227.", "228.", "229.",
    "230.", "231.", "232.", "233.", "234.",
    "235.", "236.", "237.", "238.", "239.",  # Multicast range
    "240.",         # Reserved
]

# -------------------------------------------------------
# WHITELISTED COMMON PORTS
# These ports are used by everyday legitimate software.
# We won't flag connections purely based on these ports.
# -------------------------------------------------------

SAFE_PORTS = [
    80,    # HTTP
    443,   # HTTPS
    53,    # DNS
    67,    # DHCP
    68,    # DHCP
    123,   # NTP (time sync)
    137,   # NetBIOS
    138,   # NetBIOS
    139,   # NetBIOS
    445,   # SMB (Windows file sharing)
    3389,  # RDP (Remote Desktop — only safe if you use it intentionally)
    5353,  # mDNS
    8080,  # HTTP alternate
    8443,  # HTTPS alternate
]


def get_connection_process(pid):
    """
    Given a PID, return the process name that owns this connection.
    Returns 'Unknown' if we can't access it.
    """
    if pid is None:
        return "Unknown"
    try:
        proc = psutil.Process(pid)
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "Unknown"


def resolve_hostname(ip):
    """
    Try to resolve an IP address to a hostname.
    For example: 142.250.182.46 -> google.com

    socket.gethostbyaddr() does a reverse DNS lookup.
    We set a short timeout so it doesn't slow the scan.
    We return the IP itself if resolution fails.
    """
    try:
        # Set a 1 second timeout for DNS lookups
        socket.setdefaulttimeout(1)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ip  # Just return the raw IP if lookup fails


def check_suspicious_port(port):
    """
    Check if a port number is in our suspicious ports list.
    Returns (is_suspicious, reason) tuple.
    """
    if port in SUSPICIOUS_PORTS:
        return True, SUSPICIOUS_PORTS[port]
    return False, ""


def check_suspicious_ip(ip):
    """
    Check if a remote IP address looks suspicious.
    Returns (is_suspicious, reason) tuple.
    """
    for prefix in SUSPICIOUS_IP_PREFIXES:
        if ip.startswith(prefix):
            return True, f"Connection to reserved/suspicious IP range: {ip}"
    return False, ""


def get_traffic_stats():
    """
    Get current network traffic statistics.
    psutil.net_io_counters() returns total bytes sent/received
    since the system booted.

    To get the RATE (bytes per second), we take two readings
    separated by an interval and calculate the difference.

    Returns a dictionary with bytes_sent, bytes_recv,
    packets_sent, packets_recv per second.
    """
    # First reading
    stats1 = psutil.net_io_counters()
    time.sleep(1)  # Wait 1 second
    # Second reading
    stats2 = psutil.net_io_counters()

    # Calculate difference = rate per second
    bytes_sent_per_sec  = stats2.bytes_sent  - stats1.bytes_sent
    bytes_recv_per_sec  = stats2.bytes_recv  - stats1.bytes_recv
    pkts_sent_per_sec   = stats2.packets_sent - stats1.packets_sent
    pkts_recv_per_sec   = stats2.packets_recv - stats1.packets_recv

    return {
        "bytes_sent_ps": bytes_sent_per_sec,
        "bytes_recv_ps": bytes_recv_per_sec,
        "pkts_sent_ps":  pkts_sent_per_sec,
        "pkts_recv_ps":  pkts_recv_per_sec,
        "total_bytes_sent": stats2.bytes_sent,
        "total_bytes_recv": stats2.bytes_recv,
    }


def format_bytes(byte_count):
    """
    Convert a raw byte count into a human readable string.
    Example: 1048576 -> "1.00 MB/s"
    """
    if byte_count < 1024:
        return f"{byte_count} B/s"
    elif byte_count < 1024 ** 2:
        return f"{byte_count / 1024:.2f} KB/s"
    elif byte_count < 1024 ** 3:
        return f"{byte_count / (1024**2):.2f} MB/s"
    else:
        return f"{byte_count / (1024**3):.2f} GB/s"


def detect_ddos_pattern(pkts_recv_ps, bytes_recv_ps):
    """
    Basic DDoS detection using traffic thresholds.

    A real DDoS generates enormous amounts of inbound traffic.
    These thresholds are conservative for a home machine.
    Adjust them higher for a server environment.

    Returns (is_suspicious, severity, reason)
    """
    # Thresholds
    HIGH_PACKET_RATE   = 1000   # packets per second
    HIGH_BYTE_RATE     = 10 * 1024 * 1024  # 10 MB/s

    CRITICAL_PACKET_RATE = 5000
    CRITICAL_BYTE_RATE   = 50 * 1024 * 1024  # 50 MB/s

    if pkts_recv_ps > CRITICAL_PACKET_RATE or bytes_recv_ps > CRITICAL_BYTE_RATE:
        return True, "CRITICAL", f"Extremely high inbound traffic — possible DDoS attack ({format_bytes(bytes_recv_ps)}, {pkts_recv_ps} pkts/s)"

    elif pkts_recv_ps > HIGH_PACKET_RATE or bytes_recv_ps > HIGH_BYTE_RATE:
        return True, "WARNING", f"Unusually high inbound traffic — monitor closely ({format_bytes(bytes_recv_ps)}, {pkts_recv_ps} pkts/s)"

    return False, "NORMAL", ""


def detect_port_scan(connections):
    """
    A port scan happens when one remote IP tries to connect
    to many different ports on your machine in a short time.

    We detect this by counting how many unique local ports
    each remote IP is connecting to.

    If one remote IP hits 10+ different ports = likely a scan.
    """
    # Dictionary: remote_ip -> set of local ports it's connecting to
    ip_to_ports = {}

    for conn in connections:
        # Only look at connections with a remote address
        if conn.raddr:
            remote_ip = conn.raddr.ip
            local_port = conn.laddr.port

            if remote_ip not in ip_to_ports:
                ip_to_ports[remote_ip] = set()
            ip_to_ports[remote_ip].add(local_port)

    # Flag any IP hitting 10 or more different ports
    scanners = []
    for ip, ports in ip_to_ports.items():
        if len(ports) >= 10:
            scanners.append({
                "ip": ip,
                "ports_hit": len(ports),
                "ports": sorted(list(ports))
            })

    return scanners


def analyze_connections():
    """
    MAIN ANALYSIS FUNCTION.

    Gets all active network connections, analyzes each one,
    and returns a full report dictionary.
    """

    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    suspicious_connections = []
    normal_connections = []
    all_connections_data = []

    print("\n[*] Reading active network connections...")

    try:
        # psutil.net_connections() returns all active connections
        # 'inet' means only IPv4 and IPv6 (excludes Unix sockets)
        connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        print("\n[!] Access Denied. Please run as Administrator for full results.")
        connections = []

    print(f"[*] Found {len(connections)} active connections.")
    print("[*] Analyzing each connection...\n")

    for conn in connections:
        # Skip connections with no remote address
        # (these are just listening ports, not active connections)
        if not conn.raddr:
            continue

        remote_ip   = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port  = conn.laddr.port
        status      = conn.status
        pid         = conn.pid
        proc_name   = get_connection_process(pid)

        is_suspicious = False
        reasons = []
        risk_score = 0

        # ---- CHECK 1: Suspicious remote port ----
        flagged, reason = check_suspicious_port(remote_port)
        if flagged:
            is_suspicious = True
            reasons.append(f"Suspicious remote port {remote_port}: {reason}")
            risk_score += 3

        # ---- CHECK 2: Suspicious local port ----
        # If something on YOUR machine is LISTENING on a bad port
        flagged, reason = check_suspicious_port(local_port)
        if flagged and status == "LISTEN":
            is_suspicious = True
            reasons.append(f"Listening on suspicious port {local_port}: {reason}")
            risk_score += 3

        # ---- CHECK 3: Suspicious IP ----
        flagged, reason = check_suspicious_ip(remote_ip)
        if flagged:
            is_suspicious = True
            reasons.append(reason)
            risk_score += 2

        # ---- CHECK 4: Unknown process owning a connection ----
        # Legitimate connections are almost always owned by
        # a named process. "Unknown" is a red flag.
        if proc_name == "Unknown" and status == "ESTABLISHED":
            is_suspicious = True
            reasons.append("Active connection owned by unknown/hidden process")
            risk_score += 2

        # Build connection data dictionary
        conn_data = {
            "local_port":   local_port,
            "remote_ip":    remote_ip,
            "remote_port":  remote_port,
            "status":       status,
            "pid":          pid,
            "process":      proc_name,
            "risk_score":   risk_score,
            "reasons":      reasons
        }

        all_connections_data.append(conn_data)

        if is_suspicious:
            suspicious_connections.append(conn_data)
        else:
            normal_connections.append(conn_data)

    # ---- Port scan detection ----
    try:
        raw_connections = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        raw_connections = []

    port_scanners = detect_port_scan(raw_connections)

    # ---- Traffic rate analysis ----
    print("[*] Measuring traffic rates (takes 1 second)...")
    traffic = get_traffic_stats()

    # ---- DDoS pattern detection ----
    ddos_flagged, ddos_severity, ddos_reason = detect_ddos_pattern(
        traffic["pkts_recv_ps"],
        traffic["bytes_recv_ps"]
    )

    # ---- Overall risk level ----
    num_suspicious = len(suspicious_connections)

    if ddos_flagged and ddos_severity == "CRITICAL":
        risk_level = "CRITICAL"
    elif num_suspicious == 0 and not port_scanners:
        risk_level = "SAFE"
    elif num_suspicious <= 2:
        risk_level = "LOW"
    elif num_suspicious <= 5:
        risk_level = "MEDIUM"
    elif num_suspicious <= 10:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "scan_time":              scan_time,
        "total_connections":      len(all_connections_data),
        "suspicious_connections": suspicious_connections,
        "normal_connections":     normal_connections,
        "port_scanners":          port_scanners,
        "traffic":                traffic,
        "ddos_flagged":           ddos_flagged,
        "ddos_severity":          ddos_severity,
        "ddos_reason":            ddos_reason,
        "risk_level":             risk_level,
    }


def display_network_results(result):
    """
    Prints the full network analysis report.
    """
    t = result["traffic"]

    print("\n" + "="*60)
    print("       CYBERSHIELD — NETWORK TRAFFIC ANALYSIS")
    print("="*60)
    print(f"  Scan Time          : {result['scan_time']}")
    print(f"  Active Connections : {result['total_connections']}")
    print(f"  Suspicious Found   : {len(result['suspicious_connections'])}")
    print(f"  Overall Risk       : {result['risk_level']}")
    print("="*60)

    # ---- Traffic Stats ----
    print("\n  📊 LIVE TRAFFIC RATES:")
    print(f"     Inbound  : {format_bytes(t['bytes_recv_ps'])}")
    print(f"     Outbound : {format_bytes(t['bytes_sent_ps'])}")
    print(f"     Packets In  : {t['pkts_recv_ps']} pkts/s")
    print(f"     Packets Out : {t['pkts_sent_ps']} pkts/s")
    print(f"     Total Received : {t['total_bytes_recv'] / (1024**2):.2f} MB (since boot)")
    print(f"     Total Sent     : {t['total_bytes_sent'] / (1024**2):.2f} MB (since boot)")

    # ---- DDoS Alert ----
    if result['ddos_flagged']:
        print(f"\n  🚨 DDOS ALERT [{result['ddos_severity']}]:")
        print(f"     {result['ddos_reason']}")
    else:
        print("\n  ✅ No DDoS pattern detected.")

    # ---- Port Scan Alert ----
    if result['port_scanners']:
        print(f"\n  🚨 PORT SCAN DETECTED:")
        for scanner in result['port_scanners']:
            print(f"     IP: {scanner['ip']} hit {scanner['ports_hit']} ports")
            print(f"     Ports: {scanner['ports']}")
    else:
        print("  ✅ No port scan activity detected.")

    # ---- Suspicious Connections ----
    if result['suspicious_connections']:
        print(f"\n  ⚠️  SUSPICIOUS CONNECTIONS ({len(result['suspicious_connections'])}):\n")
        for i, conn in enumerate(result['suspicious_connections'], 1):
            print(f"  [{i}] Process      : {conn['process']} (PID {conn['pid']})")
            print(f"      Remote       : {conn['remote_ip']}:{conn['remote_port']}")
            print(f"      Local Port   : {conn['local_port']}")
            print(f"      Status       : {conn['status']}")
            print(f"      Risk Score   : {conn['risk_score']}")
            print(f"      Reasons      :")
            for reason in conn['reasons']:
                print(f"        • {reason}")
            print()
    else:
        print("\n  ✅ No suspicious connections found.")

    # ---- All Active Connections Summary ----
    if result['normal_connections']:
        print(f"\n  🌐 ALL ACTIVE CONNECTIONS ({len(result['normal_connections'])} clean):\n")
        print(f"  {'PROCESS':<20} {'REMOTE IP':<18} {'PORT':<8} {'STATUS'}")
        print(f"  {'-'*20} {'-'*18} {'-'*8} {'-'*15}")
        for conn in result['normal_connections'][:15]:  # Show max 15
            print(f"  {conn['process']:<20} {conn['remote_ip']:<18} {conn['remote_port']:<8} {conn['status']}")
        if len(result['normal_connections']) > 15:
            print(f"\n  ... and {len(result['normal_connections']) - 15} more connections.")

    print("\n" + "="*60)
    print("  ℹ️  NOTE: Rule-based detection only.")
    print("  Investigate before blocking any connection.")
    print("="*60 + "\n")