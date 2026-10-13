import hashlib
import math
import re

try:
    import pefile
except ImportError:
    pefile = None

try:
    import yara
except ImportError:
    yara = None

# =====================================================================
# REGULI YARA STATICE (COMPILATE SAU SIMULATE PRIN REGEX BINAR)
# =====================================================================

YARA_RULES_SOURCE = """
rule Detect_UPX_Packer {
    meta:
        description = "Detecteaza antetul si sectiunile specifice packer-ului UPX"
        severity = "HIGH"
        weight = 35
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "!UPX" ascii
    condition:
        any of them
}

rule Detect_Suspicious_PowerShell {
    meta:
        description = "Detecteaza comenzi ascunse PowerShell sau download de payload"
        severity = "CRITICAL"
        weight = 40
    strings:
        $ps1 = "powershell" nocase ascii wide
        $ps2 = "-enc" nocase ascii wide
        $ps3 = "-encodedcommand" nocase ascii wide
        $ps4 = "DownloadString" nocase ascii wide
        $ps5 = "IEX" nocase ascii wide
        $ps6 = "bypass" nocase ascii wide
    condition:
        $ps1 and (2 of ($ps2, $ps3, $ps4, $ps5, $ps6))
}

rule Detect_C2_Network_Artifacts {
    meta:
        description = "Detecteaza siruri de comunicatie C2, URL-uri sau apeluri de retea din payload"
        severity = "MEDIUM"
        weight = 25
    strings:
        $http1 = "http://" nocase ascii wide
        $http2 = "https://" nocase ascii wide
        $c2_1  = "/api/beacon" nocase ascii wide
        $c2_2  = "/gate.php" nocase ascii wide
        $c2_3  = "socket" nocase ascii wide
        $c2_4  = "connect" nocase ascii wide
    condition:
        ($http1 or $http2) or (2 of ($c2_1, $c2_2, $c2_3, $c2_4))
}

rule Detect_Process_Injection_APIs {
    meta:
        description = "Detecteaza functii API tipice pentru Process Injection / Memory Hollowing"
        severity = "HIGH"
        weight = 35
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "QueueUserAPC" ascii wide
        $api5 = "NtMapViewOfSection" ascii wide
    condition:
        2 of them
}

rule Detect_Security_Test_Payload {
    meta:
        description = "Detecteaza semnatura de test standard EICAR sau binar de securitate FLARE/Atomic"
        severity = "CRITICAL"
        weight = 40
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii wide
        $flare1 = "Challenge1" ascii wide
        $flare2 = "flare-on" nocase ascii wide
    condition:
        any of them
}
"""

_compiled_yara = None
if yara:
    try:
        _compiled_yara = yara.compile(source=YARA_RULES_SOURCE)
    except Exception as e:
        print(f"[YARA Init Warning] Nu s-au putut compila regulile YARA native: {e}")


def _evaluate_yara_rules(data_bytes):
    """Evalueaza setul de reguli YARA pe continutul brut al fisierului."""
    matches_info = []

    # 1. Daca modulul nativ yara-python este disponibil
    if _compiled_yara:
        try:
            matches = _compiled_yara.match(data=data_bytes)
            for m in matches:
                matches_info.append({
                    "rule": m.rule,
                    "description": m.meta.get("description", ""),
                    "severity": m.meta.get("severity", "MEDIUM"),
                    "weight": int(m.meta.get("weight", 20))
                })
            return matches_info
        except Exception:
            pass

    # 2. Fallback Euristic (Regex pe Bytecode brut) daca yara-python nu e compilat
    lower_bytes = data_bytes.lower()

    # Rule 1: UPX
    if b"UPX0" in data_bytes or b"UPX1" in data_bytes or b"!UPX" in data_bytes:
        matches_info.append({
            "rule": "Detect_UPX_Packer",
            "description": "Detectat antet / sectiuni specifice packer-ului UPX (Obfuscare / Evasion)",
            "severity": "HIGH",
            "weight": 35
        })

    # Rule 2: PowerShell Ascuns
    if b"powershell" in lower_bytes and any(k in lower_bytes for k in [b"-enc", b"-encodedcommand", b"downloadstring", b"bypass", b"iex"]):
        matches_info.append({
            "rule": "Detect_Suspicious_PowerShell",
            "description": "Comanda PowerShell mascata sau apel WebClient de descarcare payload",
            "severity": "CRITICAL",
            "weight": 40
        })

    # Rule 3: C2 Network
    if b"http://" in lower_bytes or b"https://" in lower_bytes or b"/gate.php" in lower_bytes or (b"socket" in lower_bytes and b"connect" in lower_bytes):
        matches_info.append({
            "rule": "Detect_C2_Network_Artifacts",
            "description": "Siruri de comunicatie externa HTTP/Socket asociate cu C2 Beaconing",
            "severity": "MEDIUM",
            "weight": 25
        })

    # Rule 4: Process Injection
    inj_count = sum(1 for api in [b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread", b"QueueUserAPC", b"NtMapViewOfSection"] if api in data_bytes)
    if inj_count >= 2:
        matches_info.append({
            "rule": "Detect_Process_Injection_APIs",
            "description": "APIs suspecte de alocare memorie si creare thread in procese externe",
            "severity": "HIGH",
            "weight": 35
        })

    # Rule 5: Semnătură Test Standard (EICAR / FLARE)
    if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data_bytes or b"Challenge1" in data_bytes or b"flare-on" in lower_bytes:
        matches_info.append({
            "rule": "Detect_Security_Test_Payload",
            "description": "Semnătură de test standard identificată (EICAR / FLARE Sample)",
            "severity": "CRITICAL",
            "weight": 40
        })

    return matches_info


# =====================================================================
# CALCUL ENTROPIE SHANNON & FUNCTII AUXILIARE
# =====================================================================

def calculate_shannon_entropy(data_bytes):
    """Calculeaza entropia Shannon (0.0 - 8.0). Valorile > 7.0 indica compresiune/criptare."""
    if not data_bytes:
        return 0.0

    entropy = 0.0
    length = len(data_bytes)
    byte_counts = [0] * 256

    for b in data_bytes:
        byte_counts[b] += 1

    for count in byte_counts:
        if count > 0:
            p_x = float(count) / length
            entropy -= p_x * math.log(p_x, 2)

    return round(entropy, 4)


SUSPICIOUS_IAT_APIS = {
    "VirtualAlloc": 15,
    "VirtualAllocEx": 25,
    "VirtualProtect": 20,
    "WriteProcessMemory": 25,
    "CreateRemoteThread": 30,
    "LoadLibraryA": 10,
    "LoadLibraryW": 10,
    "GetProcAddress": 10,
    "WinExec": 20,
    "ShellExecuteA": 20,
    "ShellExecuteW": 20,
    "URLDownloadToFileA": 30,
    "URLDownloadToFileW": 30,
    "InternetOpenA": 15,
    "HttpOpenRequestA": 20,
    "HttpSendRequestA": 20,
    "RegSetValueExA": 15,
    "CreateProcessA": 15,
    "CreateProcessW": 15
}


def analyze_pe_bytes(file_bytes, file_name="unknown.bin"):
    """
    Analiza binară completă:
    1. Hash-uri criptografice (SHA-256, MD5)
    2. Entropie Shannon globală și pe secțiuni (.text, .data, etc.)
    3. Verificare IAT (Import Address Table) pentru APIs de injectare/evaziune
    4. Evaluare motor Reguli YARA (UPX, PowerShell, C2, Injection, Test Signatures)
    5. Fuziune de scoruri și verdict final
    """
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    md5_hash = hashlib.md5(file_bytes).hexdigest()
    global_entropy = calculate_shannon_entropy(file_bytes)

    findings = []
    suspicious_score = 0
    sections_analysis = []
    matched_apis = []

    # 1. Reguli YARA
    yara_matches = _evaluate_yara_rules(file_bytes)
    for ym in yara_matches:
        suspicious_score += ym["weight"]
        findings.append(f"[YARA: {ym['rule']}] {ym['description']}")

    # 2. Entropie Globală
    if global_entropy >= 7.1:
        suspicious_score += 35
        findings.append(f"Entropie globală ridicată ({global_entropy}/8.0): Indicator puternic de packer sau payload criptat.")
    elif global_entropy >= 6.5:
        suspicious_score += 15
        findings.append(f"Entropie globală moderată ({global_entropy}/8.0).")

    # 3. Analiză structurală PE (dacă este binar PE valid)
    is_valid_pe = False
    if pefile and len(file_bytes) >= 64:
        try:
            pe = pefile.PE(data=file_bytes)
            is_valid_pe = True

            # Secțiuni
            for section in pe.sections:
                s_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                s_entropy = round(section.get_entropy(), 4)
                s_size = section.SizeOfRawData
                sections_analysis.append({
                    "name": s_name,
                    "entropy": s_entropy,
                    "raw_size": s_size,
                    "is_packed": s_entropy >= 7.0
                })
                if s_entropy >= 7.2:
                    suspicious_score += 20
                    findings.append(f"Secțiunea '{s_name}' are entropie mare ({s_entropy}), sugerând conținut criptat/împachetat.")

            # IAT (Import Address Table)
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            if func_name in SUSPICIOUS_IAT_APIS:
                                matched_apis.append({
                                    "api": func_name,
                                    "library": entry.dll.decode('utf-8', errors='ignore'),
                                    "risk_weight": SUSPICIOUS_IAT_APIS[func_name]
                                })
                                suspicious_score += SUSPICIOUS_IAT_APIS[func_name]

            if matched_apis:
                api_names = [a["api"] for a in matched_apis[:5]]
                findings.append(f"Importuri IAT suspecte identificate ({len(matched_apis)} apeluri): {', '.join(api_names)}")

        except Exception as pe_err:
            findings.append(f"Nu s-au putut procesa structurile PE standard: {str(pe_err)[:80]}")

    # Normalizare scor între 0.0 și 1.0
    file_risk_score = round(min(1.0, suspicious_score / 100.0), 2)

    if file_risk_score >= 0.70:
        verdict = "MALICIOUS"
    elif file_risk_score >= 0.40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {
        "file_name": file_name,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "entropy": global_entropy,
        "is_valid_pe": is_valid_pe,
        "sections": sections_analysis,
        "matched_apis": matched_apis,
        "yara_matches": yara_matches,
        "findings": findings,
        "file_risk_score": file_risk_score,
        "verdict": verdict
    }