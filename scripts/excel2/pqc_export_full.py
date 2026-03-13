#!/usr/bin/env python3
"""Generate PQC workbook (SBOM/CBOM/RiskRegister/RiskAssessment) from 4 JSON inputs.

Inputs:
  1) Syft SBOM JSON
  2) Grype vulnerability JSON
  3) Semgrep CBOM JSON
  4) mini_pqc JSON (reserved for future linkage)

Usage:
  python3 pqc_export_full.py --sbom 1_syft.json --grype 2_grype.json --cbom 4_semgrep_cbom.json --mini 3_mini_pqc.json --out pqc_report.xlsx
"""

import json, os
from collections import defaultdict
from openpyxl import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Alignment, PatternFill

def load_json(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)

def autosize(ws, max_width=80):
    for col in ws.columns:
        max_len = 0
        col_letter = get_column_letter(col[0].column)
        for cell in col:
            v = cell.value
            if v is None:
                continue
            max_len = max(max_len, len(str(v)))
        ws.column_dimensions[col_letter].width = min(max_len + 2, max_width)

def style_header(ws, row=1):
    fill = PatternFill("solid", fgColor="1F4E79")
    font = Font(color="FFFFFF", bold=True)
    align = Alignment(vertical="center", wrap_text=True)
    for c in ws[row]:
        c.fill = fill
        c.font = font
        c.alignment = align
    ws.freeze_panes = "A2"

def wrap_all(ws, start_row=2):
    for row in ws.iter_rows(min_row=start_row):
        for c in row:
            c.alignment = Alignment(vertical="top", wrap_text=True)

def worst_severity_rank(sev):
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": 0, "": 0, None: 0}
    return order.get((sev or "").strip().lower(), 0)

def worst_severity_to_level(sev):
    sev = (sev or "").strip().lower()
    if sev == "critical": return "Sangat Tinggi"
    if sev == "high":     return "Tinggi"
    if sev == "medium":   return "Sederhana"
    if sev == "low":      return "Rendah"
    if sev in ("negligible","unknown"): return "Rendah"
    return ""

def parse_grype_worst_severity_by_pkg(grype):
    worst = {}
    for m in grype.get("matches") or []:
        art = m.get("artifact") or {}
        vuln = m.get("vulnerability") or {}
        key = (art.get("name") or "", art.get("version") or "", art.get("type") or "")
        sev = vuln.get("severity") or ""
        if key not in worst or worst_severity_rank(sev) > worst_severity_rank(worst[key]):
            worst[key] = sev
    return worst

def extract_project_name(sbom):
    src = sbom.get("source") or {}
    target = src.get("target") or ""
    if target:
        return os.path.basename(os.path.normpath(target)) or target
    return "UnknownProject"

def extract_url_from_syft_artifact(art):
    md = art.get("metadata") or {}
    if isinstance(md, dict):
        for k in ("homepage", "url"):
            if md.get(k): return md.get(k)
        src = md.get("source")
        if isinstance(src, dict) and src.get("url"): return src.get("url")
        dist = md.get("dist")
        if isinstance(dist, dict) and dist.get("url"): return dist.get("url")
    return ""

def parse_syft_sbom_rows(sbom, grype_worst):
    project = extract_project_name(sbom)
    rows = []
    for i, art in enumerate(sbom.get("artifacts") or [], start=1):
        name = art.get("name") or ""
        version = art.get("version") or ""
        typ = art.get("type") or ""
        url = extract_url_from_syft_artifact(art)
        worst_sev = grype_worst.get((name, version, typ), "")
        rows.append({
            "#": i,
            "System / Application": project,
            "Purpose / Usage": "",
            "URL": url,
            "Services Mode": "",
            "Target Customer": "",
            "Software Component": f"{name} {version}".strip(),
            "Third-party Modules": "",
            "External APIs or Services": "",
            "Critical Level": worst_severity_to_level(worst_sev),
            "Data Category": "",
            "Is the application/system currently in use?": "",
            "Application/System Developer": "",
            "Vendor's Name": "",
            "Does the agency have expertise?": "",
            "Does the agency have a special budget allocation?": "",
            "Link to CBOM": f"CBOM ({project})"
        })
    return rows

def parse_cbom_rows(cbom):
    results = []
    if isinstance(cbom, dict):
        if isinstance(cbom.get("results"), list):
            results = cbom["results"]
        elif isinstance(cbom.get("runs"), list):
            results = (cbom["runs"][0].get("results") or []) if cbom["runs"] else []

    def best_location(r):
        path = r.get("path") or ""
        line = None
        if isinstance(r.get("start"), dict):
            line = r["start"].get("line")
        if not path:
            locs = r.get("locations") or []
            if locs:
                pl = (locs[0].get("physicalLocation") or {})
                al = (pl.get("artifactLocation") or {})
                path = al.get("uri") or ""
                region = pl.get("region") or {}
                line = region.get("startLine")
        return path, line

    def pick(meta, *keys, default=""):
        for k in keys:
            if k in meta and meta[k] not in (None, ""):
                return meta[k]
        return default

    rows = []
    for idx, r in enumerate(results, start=1):
        meta = ((r.get("extra") or {}).get("metadata") or {})
        path, line = best_location(r)
        file_loc = path or ""
        if line:
            file_loc = f"{file_loc} (line {line})"
        rows.append({
            "# (CBOM)": f"2.{idx}",
            "System / Application": pick(meta, "system_application","system","application", default="(Unknown)"),
            "Cryptographic Function": pick(meta, "cryptographic_function","crypto_function","function"),
            "Algorithm Used": pick(meta, "algorithm_used","algorithm","alg"),
            "Algorithm Category": pick(meta, "algorithm_category","category"),
            "Library / Module": pick(meta, "library_module","library","module"),
            "File / Location": file_loc,
            "Key Length": pick(meta, "key_length","keylen"),
            "Purpose / Usage": pick(meta, "purpose_usage","purpose","usage"),
            "Crypto-Agility Support": pick(meta, "crypto_agility_support","crypto_agility","agility"),
        })
    return rows

def risk_templates_from_cbom(cbom_rows):
    rr, ra = [], []
    for i, row in enumerate(cbom_rows, start=1):
        sys_app = row.get("System / Application","")
        algo = row.get("Algorithm Used","")
        cat = (row.get("Algorithm Category") or "").lower()
        func = (row.get("Cryptographic Function") or "").lower()

        is_asym = any(x in cat for x in ["asymmetric","ecc","rsa","dsa","ecdsa","ecdh","signature","kem"]) or any(x in (algo or "").lower() for x in ["rsa","ecdsa","ecdh","dsa","dh","ed25519"])
        is_hash = "hash" in cat or "hash" in func or any(x in (algo or "").lower() for x in ["md5","sha1","sha-1","sha256","sha-256","sha3","sha-3","blake","ripemd"])
        is_sym = any(x in cat for x in ["symmetric","aead","cipher"]) or any(x in (algo or "").lower() for x in ["aes","chacha","3des","des","rc4","blowfish"])

        if is_asym:
            risk = "PQC Vulnerability: Encryption/Signature broken by Quantum Computer"
            ra_risk = "Exposure to Shor's Algorithm (Quantum Integer Factorization)"
            punca = f"Usage of Asymmetric algorithm ({algo}) which is not quantum-resistant"
            impak, like, level, mitigation = 5, 5, "Sangat Tinggi", "Migrate to NIST PQC Standards (ML-KEM/ML-DSA)"
        elif is_hash or is_sym:
            risk = "PQC Vulnerability: Brute-force resistance reduced by 50%"
            ra_risk = "Exposure to Grover's Algorithm (Quantum Search)"
            kind = "Hash" if is_hash else "Symmetric"
            punca = f"Usage of {kind} algorithm ({algo}) which is not quantum-resistant"
            impak, like = 3, 3
            level = "Rendah" if is_hash else "Sederhana"
            mitigation = "Double Key Length / Digest Size (e.g., AES-128 -> AES-256)"
        else:
            risk = "PQC Readiness: Crypto usage requires review"
            ra_risk = "PQC exposure unclear"
            punca = f"Cryptographic usage ({algo}) requires classification"
            impak, like, level, mitigation = 3, 2, "Rendah", "Perform crypto inventory + classify per PQC migration guidance"

        rr.append({
            "#": i,
            "Nama Sistem/ Perkakasan/Perisian": sys_app,
            "Jenis Aset": "Application Code",
            "Algoritma Kriptografi": algo,
            "Kegunaan Algoritma Kriptografi": row.get("Purpose / Usage","") or row.get("Cryptographic Function",""),
            "Tahap Kritikal": "Kritikal",
            "Risiko": risk,
            "Pemilik Risiko": "IT Security Team"
        })
        ra.append({
            "#": i,
            "Nama Sistem/ Perkakasan/Perisian": sys_app,
            "Algoritma Kriptografi": algo,
            "Risiko": ra_risk,
            "Punca Risiko": punca,
            "Impak": impak,
            "Kemungkinan (Likelihood)": like,
            "Skor Risiko": impak * like,
            "Risk Level": level,
            "Kawalan Sedia Ada": "Standard IT Security Controls",
            "Mitigation Plan": mitigation
        })
    return rr, ra

def write_sheet(ws, headers, rows):
    ws.append(headers)
    for r in rows:
        ws.append([r.get(h, "") for h in headers])
    style_header(ws)
    wrap_all(ws, 2)
    autosize(ws)

def main(sbom_path, grype_path, cbom_path, mini_path, out_path):
    sbom = load_json(sbom_path)
    grype = load_json(grype_path)
    cbom = load_json(cbom_path)
    _mini = load_json(mini_path)

    grype_worst = parse_grype_worst_severity_by_pkg(grype)
    sbom_rows = parse_syft_sbom_rows(sbom, grype_worst)
    cbom_rows = parse_cbom_rows(cbom)
    rr_rows, ra_rows = risk_templates_from_cbom(cbom_rows)

    wb = Workbook()
    wb.remove(wb.active)

    ws1 = wb.create_sheet("1_SBOM")
    sbom_headers = [
        "#","System / Application","Purpose / Usage","URL","Services Mode","Target Customer",
        "Software Component","Third-party Modules","External APIs or Services","Critical Level",
        "Data Category","Is the application/system currently in use?","Application/System Developer",
        "Vendor's Name","Does the agency have expertise?","Does the agency have a special budget allocation?",
        "Link to CBOM"
    ]
    write_sheet(ws1, sbom_headers, sbom_rows)

    ws2 = wb.create_sheet("2_CBOM")
    cbom_headers = ["# (CBOM)","System / Application","Cryptographic Function","Algorithm Used","Algorithm Category",
                    "Library / Module","File / Location","Key Length","Purpose / Usage","Crypto-Agility Support"]
    write_sheet(ws2, cbom_headers, cbom_rows)

    ws3 = wb.create_sheet("3_RiskRegister")
    rr_headers = ["#","Nama Sistem/ Perkakasan/Perisian","Jenis Aset","Algoritma Kriptografi","Kegunaan Algoritma Kriptografi",
                  "Tahap Kritikal","Risiko","Pemilik Risiko"]
    write_sheet(ws3, rr_headers, rr_rows)

    ws4 = wb.create_sheet("4_RiskAssessment")
    ra_headers = ["#","Nama Sistem/ Perkakasan/Perisian","Algoritma Kriptografi","Risiko","Punca Risiko","Impak",
                  "Kemungkinan (Likelihood)","Skor Risiko","Risk Level","Kawalan Sedia Ada","Mitigation Plan"]
    write_sheet(ws4, ra_headers, ra_rows)

    wb.save(out_path)

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--grype", required=True)
    ap.add_argument("--cbom", required=True)
    ap.add_argument("--mini", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    main(args.sbom, args.grype, args.cbom, args.mini, args.out)
