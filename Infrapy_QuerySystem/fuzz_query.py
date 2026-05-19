"""
fuzz_query.py
=============
Query system for the InfraPy fuzzing results database.

Supported queries:
  1. summary                        -- Overall pass/fail counts across all stages
  2. failures                       -- All expected_failure runs with error messages
  3. stage <name>                   -- All runs for a specific stage
  4. inputs <name>                  -- Find runs by input name (e.g. nan_inf_input)
  5. channel <n>                    -- All runs with a specific channel count
  6. risky                          -- Runs that passed but used out-of-range inputs

Usage:
  python fuzz_query.py --db 413db.db --interactive
  python fuzz_query.py --db 413db.db --query failures
  python fuzz_query.py --db 413db.db --query stage --stage run_fd
  python fuzz_query.py --db 413db.db --query summary
"""

import sqlite3
import argparse


# ─────────────────────────────────────────────
#  1. QUERY FUNCTIONS
# ─────────────────────────────────────────────

def summary(db_path):
    """Overall pass/fail breakdown by stage."""
    conn = sqlite3.connect(db_path)

    totals = conn.execute("""
        SELECT stage, status, COUNT(*) as cnt
        FROM   fuzzing
        GROUP  BY stage, status
        ORDER  BY stage
    """).fetchall()

    overall = conn.execute("""
        SELECT status, COUNT(*) FROM fuzzing GROUP BY status
    """).fetchall()

    conn.close()
    return totals, dict(overall)


def failures(db_path):
    """Return all expected_failure runs."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, channel_cnt, times_len, beam_rows, error
        FROM   fuzzing
        WHERE  status = 'expected_failure'
        ORDER  BY stage
    """).fetchall()
    conn.close()
    return rows


def runs_by_stage(db_path, stage_name):
    """Return all runs for a given stage."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, seed, status, error
        FROM   fuzzing
        WHERE  stage LIKE ?
        ORDER  BY status DESC, id
    """, (f"%{stage_name}%",)).fetchall()
    conn.close()
    return rows


def runs_by_input(db_path, input_name):
    """Find runs by input name."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, channel_cnt, times_len, beam_rows, status, error
        FROM   fuzzing
        WHERE  input_name LIKE ?
    """, (f"%{input_name}%",)).fetchall()
    conn.close()
    return rows


def runs_by_channel(db_path, channel_cnt):
    """Find all runs with a specific channel count."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, status, error
        FROM   fuzzing
        WHERE  channel_cnt = ?
        ORDER  BY stage
    """, (channel_cnt,)).fetchall()
    conn.close()
    return rows


def risky_runs(db_path):
    """
    Runs that PASSED but used boundary-violating inputs:
      - back_az_lim outside [0, 360]
      - channel_cnt = 0
      - n_rows <= 1
    These are the most analytically interesting — the detector
    accepted inputs it probably shouldn't have.
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, seed, status
        FROM   fuzzing
        WHERE  status = 'ok'
          AND  (
                back_az_lim > 360
             OR back_az_lim < 0
             OR channel_cnt = 0
             OR n_rows <= 1
          )
        ORDER  BY stage
    """).fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
#  2. PRINT HELPERS
# ─────────────────────────────────────────────

def divider():
    print("  " + "─" * 54)


def status_tag(s):
    return "✓ ok  " if s == "ok" else "✗ FAIL"


# ─────────────────────────────────────────────
#  3. INTERACTIVE SHELL
# ─────────────────────────────────────────────

def interactive_shell(db_path):
    print("\n========================================")
    print("  InfraPy Fuzzing Query System")
    print("========================================")
    print("\nCommands:")
    print("  summary               -- Pass/fail counts by stage")
    print("  failures              -- All failure runs + error messages")
    print("  stage <name>          -- Runs for a stage (e.g. stage run_fd)")
    print("  inputs <name>         -- Find runs by input name")
    print("  channel <n>           -- Runs with channel count = n")
    print("  risky                 -- Passed runs with out-of-range inputs")
    print("  quit")
    print("\nKnown stages: run_fk  run_fd  run_fk_pipeline  find_peaks  calc_det_thresh")
    print("Known inputs: empty_input  one_row_dataset  mismatched_shape")
    print("              nan_inf_input  bad_channel_cnt  high_back_az  negative_back_az")
    print("========================================\n")

    while True:
        try:
            raw = input("fuzz> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        if cmd == "quit":
            break

        elif cmd == "summary":
            totals, overall = summary(db_path)
            print(f"\n  Fuzzing Summary  ({sum(overall.values())} total runs)")
            divider()
            current_stage = None
            for stage, status, cnt in totals:
                if stage != current_stage:
                    print(f"\n  {stage}")
                    current_stage = stage
                tag = "✓" if status == "ok" else "✗"
                print(f"    {tag}  {status:<20} {cnt} run(s)")
            print()
            divider()
            ok  = overall.get("ok", 0)
            fail = overall.get("expected_failure", 0)
            total = ok + fail
            print(f"\n  Total:  {ok}/{total} passed  |  {fail}/{total} failed\n")

        elif cmd == "failures":
            rows = failures(db_path)
            print(f"\n  Expected Failures ({len(rows)} total)")
            divider()
            for stage, name, ch, tl, br, err in rows:
                print(f"\n  Stage:    {stage}")
                print(f"  Input:    {name or '—'}")
                print(f"  Params:   channel_cnt={ch}  times_len={tl}  beam_rows={br}")
                print(f"  Error:    {err}")
            print()

        elif cmd == "stage" and len(parts) >= 2:
            stage = parts[1]
            rows = runs_by_stage(db_path, stage)
            if not rows:
                print(f"\n  No runs found for stage '{stage}'\n")
            else:
                print(f"\n  Stage: {stage}  ({len(rows)} runs)")
                divider()
                for s, name, n_rows, ch, az, seed, status, err in rows:
                    tag = status_tag(status)
                    label = name or f"seed={seed}"
                    print(f"  [{tag}]  {label:<30}  n_rows={str(n_rows or '—'):<6}  ch={ch}  az={round(az,3) if az else 0}")
                    if err:
                        print(f"           ↳ {err}")
                print()

        elif cmd == "inputs" and len(parts) >= 2:
            name = parts[1]
            rows = runs_by_input(db_path, name)
            if not rows:
                print(f"\n  No runs found matching input '{name}'\n")
            else:
                print(f"\n  Input matches for '{name}' ({len(rows)} runs)")
                divider()
                for stage, iname, ch, tl, br, status, err in rows:
                    tag = status_tag(status)
                    print(f"  [{tag}]  {stage:<25}  input={iname}  ch={ch}  times_len={tl}")
                    if err:
                        print(f"           ↳ {err}")
                print()

        elif cmd == "channel" and len(parts) >= 2:
            try:
                ch = int(parts[1])
            except ValueError:
                print("  Please provide an integer channel count.\n")
                continue
            rows = runs_by_channel(db_path, ch)
            if not rows:
                print(f"\n  No runs with channel_cnt = {ch}\n")
            else:
                print(f"\n  Runs with channel_cnt = {ch}  ({len(rows)} total)")
                divider()
                for stage, name, n_rows, ch_, az, status, err in rows:
                    tag = status_tag(status)
                    label = name or f"n_rows={n_rows}"
                    print(f"  [{tag}]  {stage:<25}  {label:<28}  az={round(az,3) if az else 0}")
                    if err:
                        print(f"           ↳ {err}")
                print()

        elif cmd == "risky":
            rows = risky_runs(db_path)
            if not rows:
                print("\n  No risky passing runs found.\n")
            else:
                print(f"\n  Risky Passing Runs — out-of-range inputs that did NOT crash ({len(rows)} found)")
                divider()
                for stage, name, n_rows, ch, az, seed, status in rows:
                    label = name or f"seed={seed}"
                    flags = []
                    if az and (az > 360 or az < 0):
                        flags.append(f"back_az={round(az,2)} (out of [0,360])")
                    if ch == 0:
                        flags.append("channel_cnt=0")
                    if n_rows is not None and n_rows <= 1:
                        flags.append(f"n_rows={n_rows} (too small)")
                    print(f"  ✓  {stage:<25}  {label:<28}  ⚠ {', '.join(flags)}")
                print()

        else:
            print("  Unknown command. Try: summary, failures, stage <name>, inputs <name>, channel <n>, risky\n")


# ─────────────────────────────────────────────
#  4. CLI ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfraPy Fuzzing Query System")
    parser.add_argument("--db", default="413db.db", help="Path to SQLite database")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--query", choices=["summary", "failures", "stage", "risky"])
    parser.add_argument("--stage", help="Stage name for --query stage")
    args = parser.parse_args()

    if args.query == "summary":
        totals, overall = summary(args.db)
        for stage, status, cnt in totals:
            print(f"{stage:30} {status:20} {cnt}")
    elif args.query == "failures":
        for row in failures(args.db):
            print(row)
    elif args.query == "stage" and args.stage:
        for row in runs_by_stage(args.db, args.stage):
            print(row)
    elif args.query == "risky":
        for row in risky_runs(args.db):
            print(row)
    else:
        interactive_shell(args.db)
