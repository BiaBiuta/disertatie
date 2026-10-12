import math
import hashlib
import os
import json

try:
    import pefile
except ImportError:
    pefile = None

SUSPICIOUS_IMPORTS = {
    "virtualalloc", "virtualallocex", "writeprocessmemory",
    "createremotethread", "setwindowshookex", "urlcacheentry",
    "winresume", "ntunmapviewofsection", "loadlibrarya", "getprocaddress"
}

def calculate_entropy(data: bytes) -> float:
    """Calculeaza entropia Shannon (valoare intre 0.0 si 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    total_len = len(data)
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    for count in occurrences:
        if count > 0:
            p = count / total_len
            entropy -= p * math.log2(p)
    return round(entropy, 3)

def analyze_pe_bytes(raw_data: bytes, file_name: str = "unknown.exe") -> dict:
    """Extrage metadatele statice si evalueaza gradul de risc al binarului."""
    sha256_hash = hashlib.sha256(raw_data).hexdigest()
    md5_hash = hashlib.md5(raw_data).hexdigest()
    entropy = calculate_entropy(raw_data)

    findings = []
    risk_score = 0.0

    # 1. Evaluare entropie
    if entropy > 7.2:
        risk_score += 0.45
        findings.append(f"Entropie foarte ridicata ({entropy}) - potential packer/cod criptat")
    elif entropy > 6.8:
        risk_score += 0.20
        findings.append(f"Entropie usor peste medie ({entropy})")

    # 2. Inspectare antet PE cu pefile
    is_pe = False
    wx_sections = []
    flagged_apis = []

    if pefile:
        try:
            pe = pefile.PE(data=raw_data)
            is_pe = True

            # Verificare sectiuni cu permisiuni Writable + Executable
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                chars = section.Characteristics
                # 0x80000000 = IMAGE_SCN_MEM_WRITE | 0x20000000 = IMAGE_SCN_MEM_EXECUTE
                if (chars & 0x80000000) and (chars & 0x20000000):
                    wx_sections.append(sec_name)

            if wx_sections:
                risk_score += 0.35
                findings.append(f"Sectiuni hibride W+X (Write+Execute): {', '.join(wx_sections)}")

            # Verificare importuri de API-uri sensibile
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            fn_name = imp.name.decode('utf-8', errors='ignore').lower()
                            if fn_name in SUSPICIOUS_IMPORTS:
                                flagged_apis.append(fn_name)

            if flagged_apis:
                risk_score += 0.25
                unique_apis = list(set(flagged_apis))
                findings.append(f"API-uri suspecte apelate: {', '.join(unique_apis[:6])}")

        except Exception:
            findings.append("Formatul binar nu prezinta un antet PE valid")

    risk_score = min(round(risk_score, 2), 1.0)
    verdict = "MALICIOUS" if risk_score >= 0.65 else ("SUSPICIOUS" if risk_score >= 0.35 else "BENIGN")

    return {
        "file_name": file_name,
        "is_pe": is_pe,
        "sha256": sha256_hash,
        "md5": md5_hash,
        "size_bytes": len(raw_data),
        "entropy": entropy,
        "findings": findings,
        "file_risk_score": risk_score,
        "verdict": verdict
    }