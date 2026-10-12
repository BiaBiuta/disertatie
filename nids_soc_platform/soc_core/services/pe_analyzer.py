import math
import hashlib
import pefile

SUSPICIOUS_APIS = {
    'VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
    'CreateRemoteThread', 'SetWindowsHookExA', 'SetWindowsHookExW',
    'URLDownloadToFileA', 'URLDownloadToFileW', 'WinExec', 'ShellExecuteA'
}

def calculate_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    occurrences = [0] * 256
    for b in data:
        occurrences[b] += 1
    for count in occurrences:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def analyze_pe_bytes(byte_data: bytes, file_name: str = "sample.bin") -> dict:
    sha256_hash = hashlib.sha256(byte_data).hexdigest()
    md5_hash = hashlib.md5(byte_data).hexdigest()
    overall_entropy = calculate_shannon_entropy(byte_data)

    findings = []
    sections = []
    imports = []
    file_risk = 0.1

    try:
        pe = pefile.PE(data=byte_data)

        # 1. Analiza sectiunilor PE
        for s in pe.sections:
            sec_name = s.Name.decode(errors='ignore').strip('\x00')
            sec_entropy = round(s.get_entropy(), 2)
            is_wx = (s.Characteristics & 0x80000000) and (s.Characteristics & 0x20000000)

            sections.append({
                'name': sec_name,
                'entropy': sec_entropy,
                'raw_size': s.SizeOfRawData,
                'is_wx': bool(is_wx)
            })

            if sec_entropy > 7.2:
                findings.append(f"Sectiunea '{sec_name}' prezinta entropie extrema ({sec_entropy}), indicand crypter/obfuscare.")
                file_risk = max(file_risk, 0.75)

            if is_wx:
                findings.append(f"Sectiunea '{sec_name}' are permisiuni W+X (Write+Execute) - risc ridicat de unpack in memorie.")
                file_risk = max(file_risk, 0.85)

        # 2. Analiza IAT (Import Address Table)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode(errors='ignore')
                        is_suspicious = func_name in SUSPICIOUS_APIS
                        if is_suspicious:
                            findings.append(f"Import API critic detectat: {func_name} ({dll_name})")
                            file_risk = max(file_risk, 0.8)

                        imports.append({
                            'dll': dll_name,
                            'function': func_name,
                            'is_suspicious': is_suspicious
                        })
    except Exception as e:
        findings.append(f"Structura PE nestandard sau corupta: {str(e)[:60]}")
        sections.append({'name': 'RAW_DATA', 'entropy': overall_entropy, 'raw_size': len(byte_data), 'is_wx': False})

    # Calibrare verdict
    if overall_entropy > 7.4:
        file_risk = max(file_risk, 0.7)

    if file_risk >= 0.8:
        verdict = 'MALICIOUS'
    elif file_risk >= 0.5:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'BENIGN'

    return {
        'file_name': file_name,
        'sha256': sha256_hash,
        'md5': md5_hash,
        'entropy': overall_entropy,
        'file_risk_score': round(file_risk, 2),
        'verdict': verdict,
        'findings': findings,
        'sections': sections,
        'imports': imports[:30]  # primele 30 pentru performanta UI
    }