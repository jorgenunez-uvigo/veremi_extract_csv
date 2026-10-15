#!/usr/bin/env python3
"""
Parse trace JSON files (JSON-lines format) found under a root folder (recursively,
including sub-sub-folders), keep only type==3 messages (received messages, which
carry sender / senderPseudo), tag each message with the attacker id/type extracted
from its filename, and dump everything into one CSV.


Filename pattern (as given):
    traceJSON-<receiverId>-<senderId>-A<attackType>-<something>-<something>.json
We only need:
    - the file name itself -> attacker/attack-type label
    - each line inside the file -> one message (JSON object)

Ground truth files (traceGroundTruthJSON-*.json) are ignored on purpose.

Usage:
    python3 parse_traces_mixall.py /path/to/root output.csv
"""

import json
import os
import re
import sys
import csv

# ---------------------------------------------------------------------------
# EDIT HERE if you only care about a specific message type, or want more types
MESSAGE_TYPE_TO_KEEP = 3

# EDIT HERE if the filename pattern changes. Groups:
#   1 = receiver id, 2 = sender id, 3 = attack type number
FILENAME_RE = re.compile(r"traceJSON-(\d+)-(\d+)-A(\d+)-", re.IGNORECASE)
TRACEJSON_RE = re.compile(
    r"traceJSON-(?P<sender>\d+)-(?P<pseudo>\d+)-A(?P<attack_id>\d+)-(?P<time>\d+)-(?P<simid>\d+)\.json$"
)

# Filenames to always skip (ground truth files)
SKIP_PATTERNS = ("groundtruth",)

# EDIT HERE: fixed output columns. Any list-type field (pos, spd, acl, hed, ...)
# gets flattened into <field>_x/_y/_z automatically -- add the base name below
# and the x/y/z columns get added for you. Add plain scalar field names as-is.
LIST_FIELDS = ["pos", "pos_noise", "spd", "spd_noise", "acl", "acl_noise", "hed", "hed_noise"]
DATA_FIELDS = ["posx", "posy", "posz",
                  "posx_n", "posy_n", "posz_n",
                  "spdx", "spdy", "spdz",
                  "spdx_n", "spdy_n", "spdz_n",
                  "aclx", "acly", "aclz",
                  "aclx_n", "acly_n", "aclz_n",
                   "hedx", "hedy", "hedz",
                   "hedx_n", "hedy_n", "hedz_n"]
SCALAR_FIELDS = ["type", "sendTime", "sender", "senderPseudo", "messageID"]
# ---------------------------------------------------------------------------

META_COLS = [
    "class",
]


def build_columns():
    cols = list(SCALAR_FIELDS) + list(META_COLS) + list(DATA_FIELDS)
    #for base in LIST_FIELDS:
    #    for suffix in ("x", "y", "z"):
    #        cols.append(f"{base}_{suffix}")
    return cols

def find_attack_folders(root):
    subcarpetas = [f.path for f in os.scandir(root) if f.is_dir()]
    return subcarpetas

def find_trace_files(root):
    """Walk root recursively, yield trace JSON file paths, skipping ground truth."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if not fn.endswith(".json"):
                continue
            if any(p in fn.lower() for p in SKIP_PATTERNS):
                continue
            yield os.path.join(dirpath, fn)


def parse_filename(fn):
    """Extract receiver_id, attack_type from the filename."""
    m = FILENAME_RE.search(os.path.basename(fn))
    if not m:
        return None, None, None
    receiver_id, _, attack_type = m.groups()
    return receiver_id, int(attack_type)


def msg_to_row(msg,attack_class):
    row = {"posx": msg.get("pos")[0], "posy": msg.get("pos")[1], "posz": msg.get("pos")[2],
    "posx_n": msg.get("pos_noise")[0], "posy_n": msg.get("pos_noise")[1], "posz_n": msg.get("pos_noise")[2],
    "spdx": msg.get("spd")[0], "spdy": msg.get("spd")[1], "spdz": msg.get("spd")[2],
    "spdx_n": msg.get("spd_noise")[0], "spdy_n": msg.get("spd_noise")[1], "spdz_n": msg.get("spd_noise")[2],
    "aclx": msg.get("acl")[0], "acly": msg.get("acl")[1], "aclz": msg.get("acl")[2],
    "aclx_n": msg.get("acl_noise")[0], "acly_n": msg.get("acl_noise")[1], "aclz_n": msg.get("acl_noise")[2],
    "hedx": msg.get("hed")[0], "hedy": msg.get("hed")[1], "hedz": msg.get("hed")[2],
    "hedx_n": msg.get("hed_noise")[0], "hedy_n": msg.get("hed_noise")[1], "hedz_n": msg.get("hed_noise")[2],
    }
    for field in SCALAR_FIELDS:
        row[field] = msg.get(field)
    row['class']=attack_class
    return row


def process_file(filepath, writer,seen_ids,attackers):
    count = 0
    with open(filepath, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                print(f"  [!] skipping malformed line {line_num} in {filepath}")
                continue

            if msg.get("type") != MESSAGE_TYPE_TO_KEEP:
                continue

            msg_id = msg.get("messageID")
            if msg_id is not None:
                if msg_id in seen_ids:
                    continue
                seen_ids.add(msg_id)
            sender=msg.get('sender')
            if sender in attackers:
                attack_class=attackers[sender]
                #print(f"{sender}: {attack_class}")
            else:
            	print(f'sender not in attacker list: {sender}')
            	continue
            row=msg_to_row(msg,attack_class)
            writer.writerow(row)
            count += 1

    return count


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 parse_traces_mixall.py <root_folder> <output.csv>")
        sys.exit(1)

    root = sys.argv[1]
    out_csv = sys.argv[2]

    columns = build_columns()
    total_rows = 0
    total_files = 0
    attackers = {}
    with open(out_csv, "w", newline="") as out_f:
        writer = csv.DictWriter(out_f, fieldnames=columns)
        writer.writeheader()
        #attack_folders=find_attack_folders(root)
        attackers = {}
        attacks = {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: [], 8: [], 9: [], 10: [], 11: [], 12: [], 13: [],
                   14: [], 15: [], 16: [], 17: [], 18: [], 19: []}
        seen_ids = set()
        for tf in find_trace_files(root):
            changed_attack_ids = 0
            match = TRACEJSON_RE.match(os.path.basename(tf))
            if match:
                sender=int(match.group("sender"))
                attack_id = int(match.group("attack_id"))
                if sender in attackers:
                    print("REPEATED SENDER!")
                    old_attack_id = attackers[sender]
                    if attack_id!=old_attack_id:
                        print("REPEATED SENDER WITH NEW ATTACK ID")
                        changed_attack_ids+=1
                attackers[sender]=attack_id
                if attack_id:attacks[attack_id].append(sender)
            else:
                print(f"Not mached file: {os.path.basename(tf)}")
            total_files += 1
            #print(f"total_files: {total_files}")
        for tf in find_trace_files(root):
            n = process_file(tf, writer,seen_ids,attackers)
            total_rows += n
            if total_files % 50 == 0:
                print(f"  ...{total_files} files processed, {total_rows} rows so far")

        print(f"\nProcessed {total_files} file(s).")
        if total_rows == 0:
            print(f"[!] WARNING: no messages of type={MESSAGE_TYPE_TO_KEEP} were found.")
            print("    Check that your files actually contain type==3 lines,")
            print("    or change MESSAGE_TYPE_TO_KEEP at the top of this script.")
        else:
            print(f"Wrote {total_rows} rows -> {out_csv}")
            print(f"Changed attack ids: {changed_attack_ids}")


if __name__ == "__main__":
    main()
