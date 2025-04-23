import os
import re
import json
import csv
import argparse
from pathlib import Path

# 🔥 Sinks with optional filters to exclude safe variants
SINKS = {
    "memcpy":      (r"memcpy\(.*?,.*?,\s*[a-zA-Z_]", r"sizeof"),
    "strcpy":      (r"strcpy\(.*?,.*?\)", r"strncpy"),
    "strcat":      (r"strcat\(.*?,.*?\)", r"strncat"),
    "sprintf":     (r"sprintf\(.*?,.*?\)", r"snprintf"),
    "gets":        (r"gets\(.*?\)", None),
    "scanf":       (r"scanf\(\"%s\"", None),
    "system":      (r"system\(.*?\)", None),
    "exec":        (r"exec[a-z]*\(.*?\)", None),
    "fopen":       (r"fopen\(.*?,.*?\)", None),
    "read":        (r"read\(.*?,.*?,\s*[a-zA-Z_]", None),
    "write":       (r"write\(.*?,.*?,\s*[a-zA-Z_]", None),
    "malloc":      (r"malloc\(.*?\)", r"sizeof")
}

def color(text, code): return f"\033[{code}m{text}\033[0m"
def red(text): return color(text, "31")
def green(text): return color(text, "32")
def bold(text): return color(text, "1")

def scan_file(file_path, pattern, exclude=None):
    results = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                if re.search(pattern, line) and not (exclude and re.search(exclude, line)):
                    results.append({
                        "file": str(file_path),
                        "line": line_num,
                        "code": line.strip()
                    })
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
    return results

def run_scan(target_dir=".", sink_filter=None):
    print(bold("\n🔥 Running vulnscan.py 🔍\n"))
    all_results = []

    sinks_to_scan = {k: v for k, v in SINKS.items() if not sink_filter or k == sink_filter}

    for sink, (pattern, exclude) in sinks_to_scan.items():
        print(bold(f"🔎 Scanning for {sink}..."))
        count = 0

        for path in Path(target_dir).rglob("*.[cC]") | Path(target_dir).rglob("*.[cC][pP][pP]"):
            results = scan_file(path, pattern, exclude)
            for r in results:
                print(f"  📄 {r['file']}:{r['line']}: {red(r['code'])}")
                all_results.append({"sink": sink, **r})
                count += 1

        print(green("  ✅ Clean") if count == 0 else red(f"  ⚠️ {count} risky call(s) found"))
        print()

    print(bold("✅ Scan complete.\n"))
    return all_results

def export_results(results, format, output_path):
    try:
        with open(output_path, "w", encoding="utf-8", newline='') as f:
            if format == "json":
                json.dump(results, f, indent=2)
            elif format == "csv":
                writer = csv.DictWriter(f, fieldnames=["sink", "file", "line", "code"])
                writer.writeheader()
                writer.writerows(results)
        print(green(f"📦 Exported results to {output_path}"))
    except Exception as e:
        print(red(f"[!] Failed to export: {e}"))

def main():
    parser = argparse.ArgumentParser(description="🛡️ C/C++ Vulnerability Sink Scanner")
    parser.add_argument("--sink", type=str, help="Scan for a specific sink only (e.g., memcpy)")
    parser.add_argument("--export", type=str, choices=["json", "csv"], help="Export results to json or csv")
    parser.add_argument("--output", type=str, default="vulnscan_output.txt", help="Output file for exported results")
    parser.add_argument("--dir", type=str, default=".", help="Directory to scan")

    args = parser.parse_args()

    if args.sink and args.sink not in SINKS:
        print(red(f"[!] Unknown sink '{args.sink}' — use one of: {', '.join(SINKS.keys())}"))
        return

    results = run_scan(target_dir=args.dir, sink_filter=args.sink)

    if args.export:
        export_results(results, args.export, args.output)

if __name__ == "__main__":
    main()
