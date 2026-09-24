import os
import zipfile

def build_firefox_addon():
    src_dir = os.path.join(os.path.dirname(__file__), "ThreatTraceAI", "extension-firefox")
    out_file = os.path.join(os.path.dirname(__file__), "ThreatTraceAI-Firefox-v1.3.1.zip")
    
    print(f"Packaging Firefox extension from: {src_dir}")
    with zipfile.ZipFile(out_file, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(src_dir):
            if ".git" in root or "__pycache__" in root:
                continue
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, src_dir)
                zipf.write(file_path, arcname)
                print(f"  + Added: {arcname}")
                
    print(f"\n[+] Build complete: {out_file}")
    print("You can upload this ZIP directly to Mozilla Add-on Developer Hub (AMO) or load it in Firefox via about:debugging.")

if __name__ == "__main__":
    build_firefox_addon()
