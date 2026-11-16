#!/usr/bin/env python3
"""
fetch_datasets.py  —  download OTRF Security-Datasets (Empire runs) by catalog key
and extract the .json so mordor_to_mde.py can consume it.

    python3 tools/fetch_datasets.py --list
    python3 tools/fetch_datasets.py empire_schtasks_creation_execution_elevated_user
    python3 tools/fetch_datasets.py --all-tactic persistence -o datasets/raw

Handles both .zip and .tar datasets (OTRF uses both). Output is always a .json
path printed on success.
"""
import argparse
import os
import sys
import tarfile
import urllib.request
import zipfile

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"


def load_catalog():
    with open(os.path.join(ROOT, "datasets", "catalog.yaml"), encoding="utf-8") as f:
        return yaml.safe_load(f)


def resolve(key, entry):
    """key is the dataset name; entry: {tactic, ext} -> (url, filename)."""
    ext = entry.get("ext", "zip")
    fn = f"{key}.{ext}"
    url = f"{BASE}/{entry['tactic']}/host/{fn}"
    return url, fn


def extract_json(archive_path, outdir):
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as z:
            name = next(n for n in z.namelist() if n.lower().endswith(".json"))
            z.extract(name, outdir)
            return os.path.join(outdir, name)
    if archive_path.endswith((".tar", ".tar.gz", ".tgz")):
        mode = "r:gz" if archive_path.endswith((".gz", ".tgz")) else "r:"
        with tarfile.open(archive_path, mode) as t:
            member = next(m for m in t.getmembers() if m.name.lower().endswith(".json"))
            t.extract(member, outdir)
            return os.path.join(outdir, member.name)
    return archive_path  # already json


def fetch_one(key, catalog, outdir):
    entry = catalog["datasets"].get(key)
    if not entry:
        print(f"  unknown dataset: {key}", file=sys.stderr)
        return None
    url, fn = resolve(key, entry)
    os.makedirs(outdir, exist_ok=True)
    arc = os.path.join(outdir, fn)
    print(f"  downloading {key} ...")
    urllib.request.urlretrieve(url, arc)
    jpath = extract_json(arc, outdir)
    print(f"  -> {jpath}")
    return jpath


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keys", nargs="*", help="dataset keys from catalog.yaml")
    ap.add_argument("--list", action="store_true", help="list catalog datasets")
    ap.add_argument("--all-tactic", help="fetch every dataset for a tactic")
    ap.add_argument("-o", "--outdir", default="datasets/raw")
    args = ap.parse_args()
    catalog = load_catalog()
    outdir = os.path.join(ROOT, args.outdir)

    if args.list:
        for key, e in sorted(catalog["datasets"].items(), key=lambda kv: (kv[1]["tactic"], kv[0])):
            print(f"  [{e['tactic']:<20}] {key}  ({e.get('technique','-')})")
        return 0

    keys = list(args.keys)
    if args.all_tactic:
        keys += [k for k, e in catalog["datasets"].items() if e["tactic"] == args.all_tactic]
    if not keys:
        print("nothing to fetch (give a key, --all-tactic, or --list)"); return 1

    for key in keys:
        fetch_one(key, catalog, outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
