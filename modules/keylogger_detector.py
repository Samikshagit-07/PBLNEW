# modules/keylogger_detector.py

import psutil           # For reading system processes
import os               # For file path operations
import time             # For timestamps and sleep
from datetime import datetime  # For converting timestamps to readable dates

# -------------------------------------------------------
# SUSPICIOUS PROCESS NAME LIST
# These are known keylogger names, RATs (Remote Access
# Trojans), and spyware names collected from threat
# intelligence databases.
# In a real enterprise tool this list would have thousands
# of entries loaded from an external file or API.
# -------------------------------------------------------

KNOWN_MALICIOUS_NAMES = [
    # Known keyloggers
    "keylogger", "klogger", "spyagent", "revealer",
    "refog", "ardamax", "blackbox", "elite keylogger",
    "actual keylogger", "spyrix", "kidlogger",

    # Known RATs (Remote Access Trojans)
    "njrat", "darkcomet", "poison ivy", "blackshades",
    "xtreme rat", "cybergate", "quasar", "remcos",
    "nanocore", "asyncrat", "warzone",

    # Generic suspicious names attackers use to disguise malware
    "svchost32",        # Fake svchost (real one is svchost.exe)
    "lsass32",          # Fake lsass
    "csrss32",          # Fake csrss
    "winlogon32",       # Fake winlogon
    "explorer32",       # Fake explorer
    "system32.exe",     # Attackers name malware after the folder
    "svch0st",          # Zero instead of 'o' — classic trick
    "iexpl0re",         # Fake Internet Explorer
    "taskmgr32",        # Fake Task Manager
    "update.exe",       # Generic disguise name
    "patch.exe",        # Generic disguise name
    "install.exe",      # Generic disguise name
    "setup32.exe",
    "runme.exe",
    "payload.exe",
    "backdoor",
    "rootkit",
    "trojan",
    "worm.exe",
    "rat.exe",
    "hook",             # Keyboard hooking is what keyloggers do
    "keyhook",
    "hooklogger",
    "inputcapture",
]

# -------------------------------------------------------
# SUSPICIOUS KEYWORDS
# These are checked against the full process name and
# its file path. A process named "free_keylogger_v2.exe"
# wouldn't be in the list above, but the word "keylogger"
# in its name is still a red flag.
# -------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    "keylog", "keystroke", "keycap", "keyrecord",
    "spyware", "spyagent", "logger", "hooklog",
    "inputlog", "screenlog", "passlog", "spy",
    "trojan", "rootkit", "backdoor", "rat",
    "stealer", "grabber", "capture", "record",
    "monitor", "sniff", "packet", "inject"
]

# -------------------------------------------------------
# LEGITIMATE HIGH-CPU PROCESSES
# Some real system processes use CPU constantly.
# We whitelist these so they don't trigger false alarms.
# -------------------------------------------------------

WHITELISTED_PROCESSES = [
    "system", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe",
    "svchost.exe", "dwm.exe", "explorer.exe",
    "winlogon.exe", "fontdrvhost.exe", "sihost.exe",
    "taskhostw.exe", "ctfmon.exe", "spoolsv.exe",
    "audiodg.exe", "wlanext.exe", "conhost.exe",
    "dllhost.exe", "msdtc.exe", "searchindexer.exe",
    "antimalware service executable",
    "windows defender", "msmpeng.exe",
    "python.exe", "python3.exe",  # So our own script doesn't flag itself
    "code.exe", "pycharm64.exe",  # Common IDEs
]


def is_whitelisted(process_name):
    """
    Check if a process name is in our whitelist.
    Returns True if the process is known-safe.
    """
    name_lower = process_name.lower()
    for safe in WHITELISTED_PROCESSES:
        if safe.lower() in name_lower:
            return True
    return False


def check_name_against_known_malware(process_name):
    """
    Check if the process name exactly matches or closely
    resembles a known malicious program name.

    Returns: (is_suspicious: bool, reason: str)
    """
    name_lower = process_name.lower()

    # Exact match check
    for malicious in KNOWN_MALICIOUS_NAMES:
        if malicious.lower() == name_lower:
            return True, f"Exact match with known malware: '{malicious}'"

    # Partial match check (name contains the malicious name)
    for malicious in KNOWN_MALICIOUS_NAMES:
        if malicious.lower() in name_lower:
            return True, f"Name contains known malware string: '{malicious}'"

    return False, ""


def check_name_for_suspicious_keywords(process_name, exe_path=""):
    """
    Check if the process name or its file path contains
    any suspicious keyword.

    Returns: (is_suspicious: bool, reason: str)
    """
    # Combine name and path for broader keyword scanning
    combined = (process_name + " " + exe_path).lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in combined:
            return True, f"Suspicious keyword found in name/path: '{keyword}'"

    return False, ""


def check_cpu_anomaly(process):
    """
    A process that is hidden (no window, system-like name)
    but uses high CPU is suspicious.

    We take two CPU readings 0.5 seconds apart.
    cpu_percent(interval) blocks for that duration and
    returns the average CPU over that period.

    Returns: (is_suspicious: bool, cpu_value: float, reason: str)
    """
    try:
        # First call returns 0.0 always — it's just initializing
        process.cpu_percent(interval=None)
        time.sleep(0.5)
        # Second call gives the actual reading
        cpu = process.cpu_percent(interval=None)

        if cpu > 15.0:
            return True, cpu, f"Unusually high CPU usage: {cpu:.1f}%"
        return False, cpu, ""

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False, 0.0, ""


def get_process_details(process):
    """
    Safely collect all details about a process.
    We wrap every field in its own try/except because
    any single field can throw an AccessDenied error
    independently, and we don't want one failure to
    stop us from getting the other fields.

    Returns a dictionary of process info.
    """
    details = {
        "pid": "N/A",
        "name": "N/A",
        "exe": "N/A",
        "status": "N/A",
        "username": "N/A",
        "created": "N/A",
        "cmdline": "N/A",
        "cpu": 0.0
    }

    try:
        details["pid"] = process.pid
    except Exception:
        pass

    try:
        details["name"] = process.name()
    except Exception:
        pass

    try:
        details["exe"] = process.exe()
    except Exception:
        pass

    try:
        details["status"] = process.status()
    except Exception:
        pass

    try:
        details["username"] = process.username()
    except Exception:
        pass

    try:
        # create_time() returns Unix timestamp
        # We convert it to a readable format
        raw_time = process.create_time()
        details["created"] = datetime.fromtimestamp(raw_time).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        pass

    try:
        # cmdline() returns a list like ["python.exe", "main.py"]
        # We join it into a single string
        cmd = process.cmdline()
        details["cmdline"] = " ".join(cmd) if cmd else "N/A"
    except Exception:
        pass

    return details


def scan_for_keyloggers(verbose=False):
    """
    MAIN SCAN FUNCTION.
    Iterates through all running processes and checks each one
    using all our detection methods.

    verbose=True prints each process as it's being scanned
    verbose=False runs silently (used in the GUI later)

    Returns a dictionary with:
    - total_scanned: how many processes were checked
    - threats_found: list of suspicious process dictionaries
    - scan_time: when the scan was performed
    - risk_level: overall system risk (SAFE / LOW / MEDIUM / HIGH / CRITICAL)
    """

    threats_found = []
    total_scanned = 0
    scan_start = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    print("\n[*] Starting process scan... This may take a few seconds.\n")

    # psutil.process_iter() yields process objects one by one
    # We pass the attributes we want to pre-fetch for speed
    # If a process dies mid-scan, NoSuchProcess is raised — we skip it
    for process in psutil.process_iter(['pid', 'name', 'status']):

        try:
            proc_name = process.info['name'] or ""
            proc_pid  = process.info['pid']

            if not proc_name:
                continue  # Skip nameless processes

            total_scanned += 1

            if verbose:
                print(f"  Scanning PID {proc_pid:6} | {proc_name[:40]}", end="\r")

            # Skip whitelisted safe processes early
            # This improves performance and reduces false alarms
            if is_whitelisted(proc_name):
                continue

            # ---- Collect full details for suspicious checks ----
            details = get_process_details(process)
            exe_path = details["exe"] if details["exe"] != "N/A" else ""

            # Flags for this specific process
            is_suspicious = False
            reasons = []
            risk_score = 0  # Per-process risk score

            # ---- CHECK 1: Known malware name ----
            flagged, reason = check_name_against_known_malware(proc_name)
            if flagged:
                is_suspicious = True
                reasons.append(reason)
                risk_score += 3  # High weight

            # ---- CHECK 2: Suspicious keyword in name or path ----
            flagged, reason = check_name_for_suspicious_keywords(proc_name, exe_path)
            if flagged:
                is_suspicious = True
                reasons.append(reason)
                risk_score += 2  # Medium weight

            # ---- CHECK 3: CPU anomaly ----
            # Only run this check if the process is already suspicious
            # Running it on every process would slow the scan significantly
            if is_suspicious:
                flagged, cpu_val, reason = check_cpu_anomaly(process)
                if flagged:
                    reasons.append(reason)
                    risk_score += 1  # Lower weight — alone it's not enough
                details["cpu"] = cpu_val

            # ---- CHECK 4: Running from a temp or unusual directory ----
            # Legitimate software rarely runs from Temp folders
            suspicious_paths = [
                "\\temp\\", "/tmp/", "\\appdata\\local\\temp\\",
                "\\downloads\\", "\\desktop\\", "/downloads/", "/desktop/"
            ]
            if exe_path != "N/A":
                for sus_path in suspicious_paths:
                    if sus_path in exe_path.lower():
                        is_suspicious = True
                        reasons.append(f"Running from suspicious location: {exe_path}")
                        risk_score += 2
                        break

            # ---- If flagged, add to threats list ----
            if is_suspicious:
                details["reasons"] = reasons
                details["risk_score"] = risk_score
                threats_found.append(details)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process ended while we were scanning it — completely normal
            continue
        except Exception as e:
            # Catch-all for any unexpected error on a single process
            # We log it but don't stop the entire scan
            if verbose:
                print(f"\n  [!] Unexpected error on PID {process.pid}: {e}")
            continue

    # ---- Calculate overall risk level ----
    num_threats = len(threats_found)

    if num_threats == 0:
        risk_level = "SAFE"
    elif num_threats <= 2:
        risk_level = "LOW"
    elif num_threats <= 5:
        risk_level = "MEDIUM"
    elif num_threats <= 10:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    return {
        "total_scanned": total_scanned,
        "threats_found": threats_found,
        "scan_time": scan_start,
        "risk_level": risk_level,
        "threat_count": num_threats
    }


def display_scan_results(scan_result):
    """
    Prints the full scan results in a clean, readable format.
    """
    print("\n" + "="*60)
    print("         CYBERSHIELD — KEYLOGGER DETECTION RESULTS")
    print("="*60)
    print(f"  Scan Time      : {scan_result['scan_time']}")
    print(f"  Processes Scanned : {scan_result['total_scanned']}")
    print(f"  Threats Found  : {scan_result['threat_count']}")
    print(f"  Risk Level     : {scan_result['risk_level']}")
    print("="*60)

    if scan_result['threat_count'] == 0:
        print("\n  ✅ No suspicious processes detected.")
        print("  Your system appears clean based on this scan.\n")
    else:
        print(f"\n  ⚠️  {scan_result['threat_count']} SUSPICIOUS PROCESS(ES) FOUND:\n")

        for i, threat in enumerate(scan_result['threats_found'], 1):
            print(f"  [{i}] Process Name : {threat['name']}")
            print(f"      PID          : {threat['pid']}")
            print(f"      Status       : {threat['status']}")
            print(f"      User         : {threat['username']}")
            print(f"      Started At   : {threat['created']}")
            print(f"      Location     : {threat['exe']}")
            print(f"      Command      : {threat['cmdline']}")
            print(f"      Risk Score   : {threat['risk_score']}")
            print(f"      Reasons      :")
            for reason in threat['reasons']:
                print(f"        • {reason}")
            print()

    print("  ℹ️  NOTE: This tool uses rule-based detection.")
    print("  A flagged process may not always be malicious.")
    print("  Investigate before terminating any process.")
    print("="*60 + "\n")