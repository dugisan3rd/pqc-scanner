#!/usr/bin/env python3

'''Compile all JSON output to NACSA BUKUKERJA_BENGKEL MIGRASI PQC 2025'''

# ---------- START IMPORT PACKAGES ----------
from pathlib import Path
import json
from collections import defaultdict
from jsonpath_ng.ext import parse

# ---------- DECLARE ROOT FOLDER ----------
ROOT = Path(__file__).resolve().parents[1]

SYFT_SBOM_JSON_FILE = Path(ROOT / 'output' / 'raw' / '1_syft_sbom_1767674466.5739903_c1psry.json').resolve()
GRYPE_JSON_FILE = Path(ROOT / 'output' / 'raw' / '2_grype_va_1767674466.5739903_c1psry.json').resolve()
MINIPQC_JSON_FILE = Path(ROOT / 'output' / 'raw' / '3_mini_pqc_1767674466.5739903_c1psry.json').resolve()
SEMGREP_JSON_FILE = Path(ROOT / 'output' / 'raw' / '4_semgrep_cbom_1767674466.5739903_c1psry.json').resolve()


if __name__ == "__main__":
    with open(SYFT_SBOM_JSON_FILE) as f:
        SYFT_SBOM_JSON_DATA = json.load(f)
    
    with open(GRYPE_JSON_FILE) as ff:
        GRYPE_JSON_DATA = json.load(ff)

        # 1. CBOM SYFT
        expr = parse("$..purl")
        seen = set()
        i = 0
        for m in expr.find(SYFT_SBOM_JSON_DATA):
            v = m.value
            if isinstance(v, str) and v not in seen:
                seen.add(v)
                i += 1
                print(f"{i}. {v}")

        # 2. GRYPE VA
        # severity sort order (unknowns go last)
        SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

        matches_expr = parse("$.matches[*]")

        grouped = defaultdict(list)

        for m in matches_expr.find(GRYPE_JSON_DATA):
            obj = m.value

            purl_hits = parse("$.artifact.purl").find(obj)
            cve_hits = parse("$.vulnerability.id").find(obj)
            sev_hits = parse("$.vulnerability.severity").find(obj)

            purl = purl_hits[0].value if purl_hits else None
            cve = cve_hits[0].value if cve_hits else None
            sev = sev_hits[0].value if sev_hits else None

            if isinstance(purl, str) and isinstance(cve, str):
                sev = sev if isinstance(sev, str) else "Unknown"
                grouped[purl].append((cve, sev))

        # de-dup per purl (because your data has repeats)
        for purl in list(grouped.keys()):
            grouped[purl] = sorted(
                set(grouped[purl]),
                key=lambda x: (SEV_RANK.get(x[1], 99), x[0])  # severity then CVE
            )

        # Print in the format you want
        # 1. <purl>
        #   1.1 <CVE> [<SEV>]
        #   1.2 ...
        for idx, (purl, items) in enumerate(sorted(grouped.items()), start=1):
            print(f"{idx}. {purl}")
            for sub_idx, (cve, sev) in enumerate(items, start=1):
                print(f"  {idx}.{sub_idx} {cve} [{sev}]")
