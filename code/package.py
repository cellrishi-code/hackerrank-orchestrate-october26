#!/usr/bin/env python3
"""Package only runnable source, documentation, dependencies, and evaluation reports."""
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
CODE = Path(__file__).resolve().parent
FILES = [
    (CODE / "main.py", "main.py"),
    (CODE / "audit_engine.py", "audit_engine.py"),
    (CODE / "requirements.txt", "requirements.txt"),
    (CODE / "README.md", "README.md"),
    (CODE / "evaluation" / "main.py", "evaluation/main.py"),
    (CODE / "evaluation" / "evaluation_report.md", "evaluation/evaluation_report.md"),
    (CODE / "evaluation" / "usage_report.md", "evaluation/usage_report.md"),
]
DEST = ROOT / "code.zip"

def main():
    missing = [str(path.relative_to(ROOT)) for path, _ in FILES if not path.is_file()]
    if missing:
        raise SystemExit("Cannot package; required files missing: " + ", ".join(missing))
    with ZipFile(DEST, "w", compression=ZIP_DEFLATED, compresslevel=9) as zf:
        for source, target in FILES:
            zf.write(source, target)
    with ZipFile(DEST) as zf:
        names = set(zf.namelist())
        required = {"main.py","audit_engine.py","requirements.txt","README.md",
                    "evaluation/main.py","evaluation/evaluation_report.md","evaluation/usage_report.md"}
        if not required <= names:
            raise SystemExit("Archive missing required entries: " + ", ".join(sorted(required - names)))
        if any(name.startswith(("dataset/","venv/")) or name == ".env" or "site-packages" in name for name in names):
            raise SystemExit("Archive contains an excluded dataset, environment, or secret file")
        print(f"Created {DEST} with {len(names)} files ({DEST.stat().st_size} bytes).")
        for name in sorted(names): print(" - " + name)

if __name__ == "__main__":
    main()
