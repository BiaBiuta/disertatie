import os
import zipfile
import io
import urllib.request
import ssl

DEST_DIR = os.path.join(os.getcwd(), "test_binaries")
os.makedirs(DEST_DIR, exist_ok=True)

# Context SSL și User-Agent valid pentru GitHub
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
}

print(f"[*] Descărcare mostre reale de pe GitHub în: {DEST_DIR}\n")

# --------------------------------------------------------------------------
# 1. Binarul oficial EICAR de pe GitHub (depozitul fire1ce/eicar-standard-antivirus-test-files)
# --------------------------------------------------------------------------
eicar_url = "https://raw.githubusercontent.com/fire1ce/eicar-standard-antivirus-test-files/master/eicar-com.com"
eicar_dest = os.path.join(DEST_DIR, "git_eicar_test.com")
print(f"-> Descărcare EICAR din depozitul GitHub (fire1ce)...")

try:
    req = urllib.request.Request(eicar_url, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        content = resp.read()
        with open(eicar_dest, "wb") as f:
            f.write(content)
    print(f"   [OK] Descărcat: git_eicar_test.com ({len(content)} octeți)")
except Exception as e:
    print(f"   [EROARE] Descărcare eicar: {e}")

# --------------------------------------------------------------------------
# 2. Executabil PE real împachetat (UPX Release oficial de pe GitHub: upx/upx)
# --------------------------------------------------------------------------
upx_release_url = "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-win64.zip"
print(f"\n-> Descărcare pachet binar UPX din GitHub Releases (upx/upx)...")

try:
    req = urllib.request.Request(upx_release_url, headers=headers)
    with urllib.request.urlopen(req, context=ctx, timeout=25) as resp:
        zip_data = resp.read()

    # Extragem executabilul PE upx.exe direct din arhiva ZIP
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for member in zf.namelist():
            if member.endswith("upx.exe"):
                exe_content = zf.read(member)
                target_exe = os.path.join(DEST_DIR, "git_upx_packed.exe")
                with open(target_exe, "wb") as f:
                    f.write(exe_content)
                print(f"   [OK] Extras cu succes binarul real PE: git_upx_packed.exe ({len(exe_content)/1024:.2f} KB)")
                break
except Exception as e:
    print(f"   [EROARE] Descărcare UPX release: {e}")

print(f"\n[FINALIZAT] Fișierele descărcate de pe GitHub sunt disponibile în folderul 'test_binaries/'.")