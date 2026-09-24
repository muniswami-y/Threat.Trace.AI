"""
Sync Chrome extension files to Firefox extension (preserving Firefox manifest.json),
then rebuild the Firefox distribution ZIP.
"""
import os
import shutil
import zipfile

BASE = os.path.dirname(__file__)
CHROME_EXT = os.path.join(BASE, "ThreatTraceAI", "extension")
FIREFOX_EXT = os.path.join(BASE, "ThreatTraceAI", "extension-firefox")
OUT_ZIP = os.path.join(BASE, "ThreatTraceAI-Firefox-v1.3.1.zip")

def sync_extensions():
    print("=== Syncing Chrome extension -> Firefox extension ===")
    for item in os.listdir(CHROME_EXT):
        if item == "manifest.json":
            print(f"  [SKIP] {item} (Firefox has its own manifest)")
            continue
        src = os.path.join(CHROME_EXT, item)
        dst = os.path.join(FIREFOX_EXT, item)
        if os.path.isdir(src):
            if os.path.exists(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            print(f"  [DIR]  {item}")
        else:
            shutil.copy2(src, dst)
            print(f"  [FILE] {item}")
    print("Sync complete.\n")

def build_zip():
    print("=== Building Firefox ZIP ===")
    if os.path.exists(OUT_ZIP):
        os.remove(OUT_ZIP)
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(FIREFOX_EXT):
            for f in files:
                fpath = os.path.join(root, f)
                arcname = os.path.relpath(fpath, FIREFOX_EXT)
                zipf.write(fpath, arcname)
                print(f"  + {arcname}")
    print(f"\n[OK] Firefox ZIP built: {OUT_ZIP}")

if __name__ == "__main__":
    sync_extensions()
    build_zip()
