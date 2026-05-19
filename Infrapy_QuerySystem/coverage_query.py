"""
Supported queries:
  1. branch_coverage <file>              -- Coverage % and uncovered branches for a file
  2. uncovered <file>                    -- List every uncovered line in a file
  3. compare <file>                      -- Compare coverage across test runs
  4. dataflow <var>                      -- Where is a variable used/defined?
  5. dependent <var_a> <var_b>           -- Are two variables data-dependent?
  6. summary                             -- Overall coverage summary across all files

"""

import sqlite3
import argparse

#Coverage Queries

def branch_coverage(db_path: str, file_name: str):
    """
    Returns coverage % and a breakdown of covered vs uncovered branches for a file.
    """
    conn = sqlite3.connect(db_path)
 
    total = conn.execute("""
        SELECT COUNT(*) FROM coverage
        WHERE file = ?
    """, (file_name,)).fetchone()[0]
 
    covered = conn.execute("""
        SELECT COUNT(*) FROM coverage
        WHERE file = ? AND covered = 1
    """, (file_name,)).fetchone()[0]
 
    uncovered_branches = conn.execute("""
        SELECT line_number, branch_id
        FROM   coverage
        WHERE  file = ? AND covered = 0
        ORDER  BY CAST(line_number AS INTEGER)
    """, (file_name,)).fetchall()
 
    conn.close()

    if total == 0:
        return None, None, []
 
    pct = round((covered / total) * 100, 1)
    return covered, total, pct, uncovered_branches

def uncovered_lines(db_path: str, file_name: str):
    """
    Returns all uncovered line numbers for a given file.
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT DISTINCT line_number
        FROM   coverage
        WHERE  file = ? AND covered = 0
        ORDER  BY CAST(line_number AS INTEGER)
    """, (file_name,)).fetchall()
    conn.close()
    return [r[0] for r in rows]

def compare_test_runs(db_path: str, file_name: str):
    """
    Compares coverage across all test runs for a given file.
    """
    conn = sqlite3.connect(db_path)
 
    runs = conn.execute("""
        SELECT DISTINCT test_run_id FROM coverage
        WHERE file = ?
    """, (file_name,)).fetchall()
 
    results = []
    for (run_id,) in runs:
        total = conn.execute("""
            SELECT COUNT(*) FROM coverage
            WHERE file = ? AND test_run_id = ?
        """, (file_name, run_id)).fetchone()[0]
 
        covered = conn.execute("""
            SELECT COUNT(*) FROM coverage
            WHERE file = ? AND test_run_id = ? AND covered = 1
        """, (file_name, run_id)).fetchone()[0]
 
        pct = round((covered / total) * 100, 1) if total > 0 else 0
        results.append((run_id, covered, total, pct))
 
    conn.close()
    return results
 
 
def overall_summary(db_path: str):
    """
    Overall coverage summary across all files and test runs.
    """
    conn = sqlite3.connect(db_path)
 
    rows = conn.execute("""
        SELECT   file,
                 COUNT(*) AS total,
                 SUM(covered) AS covered
        FROM     coverage
        GROUP BY file
        ORDER BY file
    """).fetchall()
 
    conn.close()
 
    results = []
    for file, total, covered in rows:
        pct = round((covered / total) * 100, 1) if total > 0 else 0
        results.append((file, covered, total, pct))
    return results


#Dataflow Queries

def dataflow_lookup(db_path: str, var_name: str):
    """
    Find all functions where a variable is defined or used.
    caller = variable name, callee = function it appears in.
    """
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT caller, callee, file, line_number, extra_data
        FROM   static_analysis
        WHERE  analysis_type = 'dataflow'
          AND  (caller = ? OR callee = ?)
        ORDER  BY line_number
    """, (var_name, var_name)).fetchall()
    conn.close()
    return rows
 
def are_dependent(db_path: str, var_a: str, var_b: str):
    """
    Check if two variables share any common function — indicating data dependency.
    Returns list of functions where both variables appear.
    """
    conn = sqlite3.connect(db_path)
 
    funcs_a = set(row[0] for row in conn.execute("""
        SELECT callee FROM static_analysis
        WHERE  analysis_type = 'dataflow' AND caller = ?
    """, (var_a,)).fetchall())
 
    funcs_b = set(row[0] for row in conn.execute("""
        SELECT callee FROM static_analysis
        WHERE  analysis_type = 'dataflow' AND caller = ?
    """, (var_b,)).fetchall())
 
    conn.close()
 
    shared = sorted(funcs_a & funcs_b)
    return shared
 

#Printing helper functions

def print_divider():
    print("  " + "-" * 50)
 
 
def print_coverage_bar(pct: float, width: int = 30):
    filled = int((pct / 100) * width)
    bar = "█" * filled + "░" * (width - filled)
    print(f"  [{bar}] {pct}%")


# Interactive shell

def interactive_shell(db_path: str):
    print("\n========================================")
    print("  InfraPy Coverage Query System")
    print("========================================")
    print("\nCommands:")
    print("  branch_coverage <file>       -- Coverage % and uncovered branches")
    print("  uncovered <file>             -- All uncovered line numbers")
    print("  compare <file>               -- Compare across test runs")
    print("  dataflow <var>               -- Where is a variable used?")
    print("  dependent <var_a> <var_b>    -- Are two variables data-dependent?")
    print("  summary                      -- Overall coverage across all files")
    print("  quit                         -- Exit")
    print("========================================")
    print("\nKnown files:  beamforming_new.py  |  spectral.py  |  test_beamforming.py  |  _spectral.py")
    print("Known vars:   thresh  det_mask  fstat_vals  fstat_ref_peak")
    print("              beam_peaks  thresh_vals  det_p_val  back_az_vals")
    print("              back_az_95conf  trc_vel_vals  dets\n")
 
    while True:
        try:
            raw = input("query> ").strip()
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
            results = overall_summary(db_path)
            print(f"\n  Overall Coverage Summary")
            print_divider()
            for file, covered, total, pct in results:
                print(f"\n  {file}")
                print_coverage_bar(pct)
                print(f"  {covered}/{total} branches covered")
 
        elif cmd == "branch_coverage" and len(parts) == 2:
            file = parts[1]
            covered, total, pct, uncovered = branch_coverage(db_path, file)
            if covered is None:
                print(f"\n  No coverage data found for {file}")
            else:
                print(f"\n  Branch Coverage: {file}")
                print_divider()
                print_coverage_bar(pct)
                print(f"  {covered}/{total} branches covered")
                if uncovered:
                    print(f"\n  Uncovered branches ({len(uncovered)}):")
                    for line, branch in uncovered[:20]:
                        print(f"    line {line:>5}  branch {branch}")
                    if len(uncovered) > 20:
                        print(f"    ... and {len(uncovered) - 20} more (use 'uncovered {file}' for full list)")
 
        elif cmd == "uncovered" and len(parts) == 2:
            file = parts[1]
            lines = uncovered_lines(db_path, file)
            if not lines:
                print(f"\n  No uncovered lines found for {file} — full coverage!")
            else:
                print(f"\n  Uncovered lines in {file} ({len(lines)} total):")
                print_divider()
                # Print in rows of 10
                for i in range(0, len(lines), 10):
                    chunk = lines[i:i+10]
                    print("  " + "  ".join(f"{l:>5}" for l in chunk))
 
        elif cmd == "compare" and len(parts) == 2:
            file = parts[1]
            results = compare_test_runs(db_path, file)
            if not results:
                print(f"\n  No test run data found for {file}")
            else:
                print(f"\n  Coverage Comparison: {file}")
                print_divider()
                for run_id, covered, total, pct in results:
                    print(f"\n  Run: {run_id}")
                    print_coverage_bar(pct)
                    print(f"  {covered}/{total} branches covered")
 
        elif cmd == "dataflow" and len(parts) == 2:
            var = parts[1]
            rows = dataflow_lookup(db_path, var)
            if not rows:
                print(f"\n  No dataflow data found for variable '{var}'")
            else:
                print(f"\n  Dataflow for variable '{var}' ({len(rows)} events):")
                print_divider()
                for caller, callee, file, line, extra in rows:
                    import json
                    kind = json.loads(extra).get("kind", "?") if extra else "?"
                    ctx  = json.loads(extra).get("context", "") if extra else ""
                    print(f"  line {str(line):>5}  [{kind:<10}]  in {callee:<25}  ({ctx})")
 
        elif cmd == "dependent" and len(parts) == 3:
            var_a, var_b = parts[1], parts[2]
            shared = are_dependent(db_path, var_a, var_b)
            if shared:
                print(f"\n  YES — '{var_a}' and '{var_b}' are data-dependent")
                print(f"  Both appear in:")
                for func in shared:
                    print(f"    • {func}")
            else:
                print(f"\n  NO — '{var_a}' and '{var_b}' share no common functions")
 
        else:
            print("  Unknown command or wrong arguments. Type a command from the list above.")
 
        print()
 
 

# CLI ENTRY POINT

 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfraPy Coverage Query System")
    parser.add_argument("--db", default="413db.db", help="Path to SQLite database")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive shell")
    parser.add_argument("--query", choices=["branch_coverage", "uncovered", "compare", "dataflow", "dependent", "summary"])
    parser.add_argument("--file", help="File name to query coverage for")
    parser.add_argument("--var_a", help="First variable for dependency check")
    parser.add_argument("--var_b", help="Second variable for dependency check")
    parser.add_argument("--var", help="Variable name for dataflow lookup")
    args = parser.parse_args()
 
    if args.interactive or not args.query:
        interactive_shell(args.db)
 
    elif args.query == "summary":
        for file, covered, total, pct in overall_summary(args.db):
            print(f"{file}: {covered}/{total} ({pct}%)")
 
    elif args.query == "branch_coverage":
        covered, total, pct, uncovered = branch_coverage(args.db, args.file)
        print(f"{args.file}: {covered}/{total} branches covered ({pct}%)")
        for line, branch in uncovered:
            print(f"  line {line} branch {branch}")
 
    elif args.query == "uncovered":
        for line in uncovered_lines(args.db, args.file):
            print(f"  line {line}")
 
    elif args.query == "compare":
        for run_id, covered, total, pct in compare_test_runs(args.db, args.file):
            print(f"{run_id}: {covered}/{total} ({pct}%)")
 
    elif args.query == "dataflow":
        for row in dataflow_lookup(args.db, args.var):
            print(row)
 
    elif args.query == "dependent":
        shared = are_dependent(args.db, args.var_a, args.var_b)
        print("DEPENDENT" if shared else "NOT DEPENDENT")
        for f in shared:
            print(f"  • {f}")
