#!/usr/bin/env python3
"""
Reproducible preprocessing pipeline for AegisVault's training data.

Replaces the manual notebook run-order (ParseECML -> ParseHTTPParams ->
ParseXSS -> MergeAndClean) with a single script using paths relative to the
repo, instead of the dead hardcoded absolute paths the original notebooks
used. Produces waf/Datasets/complete_clean.json, the same artifact
MergeAndClean.ipynb used to produce.

Usage:
    python waf/Training/preprocess.py

Expects these raw files to already be in waf/Datasets/:
    learning_dataset.xml   (ECML/PKDD 2007)
    payload_train.csv      (HTTPParams train split)
    payload_test.csv       (HTTPParams test split)
    XSS_dataset.csv        (XSS-specific dataset)
"""
import json
import math
import random
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
import pandas as pd

DATASETS_DIR = Path(__file__).resolve().parent.parent / "Datasets"

ECML_XML = DATASETS_DIR / "learning_dataset.xml"
HTTPPARAMS_TRAIN_CSV = DATASETS_DIR / "payload_train.csv"
HTTPPARAMS_TEST_CSV = DATASETS_DIR / "payload_test.csv"
XSS_CSV = DATASETS_DIR / "XSS_dataset.csv"

OUTPUT_JSON = DATASETS_DIR / "complete_clean.json"

NS = "{http://www.example.org/ECMLPKDD}"


# ---------------------------------------------------------------------------
# Cleanin helpers (ported as-is from MergeAndClean.ipynb)
# ---------------------------------------------------------------------------

def unquote(text: str) -> str:
    k, prev = 0, text
    while k < 100:
        nxt = urllib.parse.unquote_plus(prev)
        if nxt == prev:
            break
        prev = nxt
        k += 1
    return prev


def remove_new_line(text: str) -> str:
    text = text.strip()
    return " ".join(text.splitlines())


def remove_multiple_whitespaces(text: str) -> str:
    return " ".join(text.split())


def clean_pattern(pattern: str) -> str:
    pattern = unquote(pattern)
    pattern = remove_new_line(pattern)
    pattern = pattern.lower()
    return remove_multiple_whitespaces(pattern)


# ---------------------------------------------------------------------------
# ECML/PKDD 2007 (ParseECML.ipynb)
# ---------------------------------------------------------------------------

def parse_ecml() -> list[dict]:
    root = ET.parse(ECML_XML).getroot()

    data = []
    for child in root:
        sample = {"id": child.attrib["id"]}
        for subchild in child:
            for subsub in subchild:
                sample[subsub.tag] = subsub.text
        data.append(sample)
    df = pd.DataFrame(data)

    final_data = []
    for _, row in df.iterrows():
        sample = {"type": row[f"{NS}type"]}
        if row[f"{NS}type"] == "Valid":
            new = True
            while new:
                c = random.randint(0, 3)
                if c == 0:
                    sample["request"] = row[f"{NS}uri"]
                elif c == 1:
                    sample["request"] = row[f"{NS}query"]
                elif c == 2:
                    sample["request"] = row[f"{NS}body"]
                elif c == 3:
                    headers = row[f"{NS}headers"].split("\n")
                    whereis = random.sample(
                        ["Cookie", "User-Agent", "Accept-Language", "Accept-Encoding"], 1
                    )[0]
                    for h in headers:
                        if h.startswith(whereis):
                            sample["request"] = h[len(whereis) + 2:].strip()
                            break
                if ("request" in sample) and (sample["request"] is not None):
                    if isinstance(sample["request"], str):
                        if sample["request"] != "nan":
                            new = False
                    elif not math.isnan(sample["request"]):
                        new = False
        else:
            interval = row[f"{NS}attackIntervall"]
            sample["interval"] = interval
            if interval.startswith("uri"):
                sample["request"] = row[f"{NS}uri"]
            elif interval.startswith("query"):
                sample["request"] = row[f"{NS}query"]
            elif interval.startswith("body"):
                sample["request"] = row[f"{NS}body"]
            elif interval.startswith("headers"):
                whereis = interval[8:]
                whereis = whereis[: whereis.find(":")]
                headers = row[f"{NS}headers"].split("\n")
                for h in headers:
                    if h.startswith(whereis):
                        sample["request"] = h[len(whereis) + 2:].strip()
                        break
        final_data.append(sample)

    final_df = pd.DataFrame(final_data)
    keep_types = ["Valid", "XSS", "SqlInjection", "PathTransversal", "OsCommanding"]
    final_df = final_df[final_df["type"].isin(keep_types)]

    label_map = {
        "Valid": "valid",
        "XSS": "xss",
        "SqlInjection": "sqli",
        "PathTransversal": "path-traversal",
        "OsCommanding": "cmdi",
    }
    records = final_df.to_dict("records")
    return [
        {"pattern": clean_pattern(str(r["request"])), "type": label_map[r["type"]]}
        for r in records
    ]


# ---------------------------------------------------------------------------
# HTTPParams (ParseHTTPParams.ipynb)
# ---------------------------------------------------------------------------

def parse_httpparams() -> list[dict]:
    train = pd.read_csv(HTTPPARAMS_TRAIN_CSV)[["payload", "attack_type"]]
    test = pd.read_csv(HTTPPARAMS_TEST_CSV)[["payload", "attack_type"]]
    full_df = pd.concat([train, test])

    out = []
    for r in full_df.to_dict("records"):
        label = "valid" if r["attack_type"] == "norm" else r["attack_type"]
        out.append({"pattern": clean_pattern(str(r["payload"])), "type": label})
    return out


# ---------------------------------------------------------------------------
# XSS-specific dataset (ParseXSS.ipynb)
# ---------------------------------------------------------------------------

def parse_xss() -> list[dict]:
    df = pd.read_csv(XSS_CSV)
    out = []
    for r in df.to_dict("records"):
        label = "xss" if r["Label"] == 1 else "valid"
        out.append({"pattern": clean_pattern(str(r["Sentence"])), "type": label})
    return out


def main():
    for path in (ECML_XML, HTTPPARAMS_TRAIN_CSV, HTTPPARAMS_TEST_CSV, XSS_CSV):
        if not path.exists():
            raise SystemExit(
                f"Missing raw dataset file: {path}\n"
                f"Place the 4 raw dataset files in {DATASETS_DIR} before running preprocess.py."
            )

    print("Parsing ECML/PKDD 2007...")
    ecml = parse_ecml()
    print(f"  {len(ecml):,} samples")

    print("Parsing HTTPParams...")
    httpparams = parse_httpparams()
    print(f"  {len(httpparams):,} samples")

    print("Parsing XSS...")
    xss = parse_xss()
    print(f"  {len(xss):,} samples")

    complete = ecml + httpparams + xss
    OUTPUT_JSON.write_text(json.dumps(complete))
    print(f"\nWrote {len(complete):,} total samples to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
