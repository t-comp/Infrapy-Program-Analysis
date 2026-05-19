import sqlite3
import collections
import argparse
import re

#
# load graph from DB
#
def load_call_graph(db_path: str) -> tuple:
    conn = sqlite3.connect(db_path)

    rows = conn.execute("""
        SELECT caller, callee
        FROM static_analysis
        WHERE analysis_type = 'call_graph'
    """).fetchall()
    conn.close()

    forward = collections.defaultdict(list)
    reverse = collections.defaultdict(list)
    for caller, callee in rows:
        forward[caller].append(callee)
        reverse[callee].append(caller)

    return dict(forward), dict(reverse)

#
# Call Graph Functions
#
def is_caller(forward, func_a, func_b):
    
    #BFS with parent tracking
    visited = {func_a}
    queue = collections.deque([[func_a]])

    while queue:
        path = queue.popleft()
        current = path[-1]

        for callee in forward.get(current, []):
            if callee == func_b:
                return True, path + [callee]
            if callee not in visited:
                visited.add(callee)
                queue.append(path + [callee])
    return False, []

def all_callees(forward, func_a):
   
    visited = set()
    queue = collections.deque([func_a])

    while queue:
        current = queue.popleft()
        for callee in forward.get(current, []):
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)

    return sorted(visited)

def all_callers(reverse, func_b):
   
    if func_b not in reverse:
        return []
    
    visited = set()
    queue = collections.deque([func_b])

    while queue:
        current = queue.popleft()
        for caller in reverse.get(current, []):
            if caller not in visited:
                visited.add(caller)
                queue.append(caller)

    return sorted(visited)

def direct_callees(forward, func_a):
    return sorted(forward.get(func_a, []))
 
def direct_callers(reverse, func_b):
    return sorted(reverse.get(func_b, []))

#
# Coverage / Dataflow Functions
#

def branch_coverage(db_path, file_name):
   
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
        return None, None, None, []
 
    pct = round((covered / total) * 100, 1)
    return covered, total, pct, uncovered_branches

def uncovered_lines(db_path, file_name):
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


def compare_test_runs(db_path, file_name):
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

def overall_summary(db_path):
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT file, COUNT(*) as total, SUM(covered) as covered
        FROM   coverage GROUP BY file ORDER BY file
    """).fetchall()
    conn.close()
    return [(f, c, t, round((c/t)*100, 1) if t else 0) for f, t, c in rows]


def dataflow_lookup(db_path, var_name):
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT caller, callee, file, line_number, extra_data
        FROM   static_analysis
        WHERE  analysis_type = 'dataflow' AND (caller = ? OR callee = ?)
        ORDER  BY line_number
    """, (var_name, var_name)).fetchall()
    conn.close()
    return rows
 
def are_dependent(db_path, var_a, var_b):
    conn = sqlite3.connect(db_path)
    funcs_a = set(r[0] for r in conn.execute("SELECT callee FROM static_analysis WHERE analysis_type='dataflow' AND caller=?", (var_a,)).fetchall())
    funcs_b = set(r[0] for r in conn.execute("SELECT callee FROM static_analysis WHERE analysis_type='dataflow' AND caller=?", (var_b,)).fetchall())
    conn.close()
    return sorted(funcs_a & funcs_b)

#Fuzzing functions
def fuzz_summary(db_path):
    """Overall pass/fail breakdown by stage."""
    conn = sqlite3.connect(db_path)
    totals = conn.execute("""
        SELECT stage, status, COUNT(*) as cnt
        FROM fuzzing GROUP BY stage, status ORDER BY stage
    """).fetchall()
    overall = conn.execute(
        "SELECT status, COUNT(*) FROM fuzzing GROUP BY status"
    ).fetchall()
    conn.close()
    return totals, dict(overall)
 
 
def fuzz_failures(db_path):
    """Return all expected_failure runs."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, channel_cnt, times_len, beam_rows, error
        FROM fuzzing WHERE status = 'expected_failure' ORDER BY stage
    """).fetchall()
    conn.close()
    return rows
 
 
def fuzz_runs_by_stage(db_path, stage_name):
    """Return all runs for a given stage."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, seed, status, error
        FROM fuzzing WHERE stage LIKE ? ORDER BY status DESC, id
    """, (f"%{stage_name}%",)).fetchall()
    conn.close()
    return rows
 
 
def fuzz_runs_by_channel(db_path, channel_cnt):
    """Find all runs with a specific channel count."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, status, error
        FROM fuzzing WHERE channel_cnt = ? ORDER BY stage
    """, (channel_cnt,)).fetchall()
    conn.close()
    return rows
 
 
def fuzz_risky_runs(db_path):
    """Runs that PASSED but used boundary-violating inputs."""
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT stage, input_name, n_rows, channel_cnt, back_az_lim, seed, status
        FROM fuzzing
        WHERE status = 'ok'
          AND (back_az_lim > 360 OR back_az_lim < 0 OR channel_cnt = 0 OR n_rows <= 1)
        ORDER BY stage
    """).fetchall()
    conn.close()
    return rows

#
# Keyword Extraction Helpers
#
KNOWN_FUNCTIONS = [
   "beam_window", "beam_window_wrapper", "build_slowness", "calc_det_thresh",
    "compute_beam_power", "compute_beam_power_wrapper", "compute_delays",
    "detect_signals", "fft_array_data", "find_peaks", "project_ABA",
    "project_ABc", "project_Ab", "run", "run_fd", "run_fk", "stream_to_array_data"
]

KNOWN_FILES = [
    "beamforming_new.py", "spectral.py", "_spectral.py", "test_beamforming.py"
]

KNOWN_VARS = [
    "thresh", "det_mask", "fstat_vals", "fstat_ref_peak", "beam_peaks",
    "thresh_vals", "det_p_val", "back_az_vals", "back_az_95conf",
    "trc_vel_vals", "dets"
]

KNOWN_FUZZ_STAGES = [
    "run_fk", "run_fd", "run_fk_pipeline", "find_peaks", "calc_det_thresh"
]

KNOWN_FUZZ_INPUTS = [
    "empty_input", "one_row_dataset", "mismatched_shape",
    "nan_inf_input", "bad_channel_cnt", "high_back_az", "negative_back_az"
]

def extract_functions(text):
    matches = []
    for f in KNOWN_FUNCTIONS:
        # Use word boundary so 'run' doesn't match inside 'run_fk'
        pattern = r'(?<![a-zA-Z_])' + re.escape(f) + r'(?![a-zA-Z_])'
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            matches.append((m.start(), f))
    matches.sort(key=lambda x: x[0])
    return [f for _, f in matches]

def extract_file(text):
    for f in KNOWN_FILES:
        if f.lower() in text.lower():
            return f
    return None

def extract_vars(text):
    return [v for v in KNOWN_VARS if v.lower() in text.lower()]

def extract_fuzz_stage(text):
    for s in KNOWN_FUZZ_STAGES:
        if s.lower() in text.lower():
            return s
    return None

def extract_channel(text):
    m = re.search(r'\bchannel\s*(?:count|cnt|=)?\s*(\d+)', text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r'\b(\d+)\s*channel', text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None
 
 
def make_bar(pct, width=20):
    filled = int(pct / 5)
    return "█" * filled + "░" * (width - filled)

#
# Keyword Router
#
def router(db_path, forward, reverse, question):
    q = question.lower()
    funcs = extract_functions(question)
    file = extract_file(question)
    vars_ = extract_vars(question)
    fstage = extract_fuzz_stage(question)
    fch = extract_channel(question)

    #Fuzzing Routes
    if any(kw in q for kw in ["fuzz", "fuzzing", "fuzz summary", "fuzzing summary"]):
 
        # summary
        if any(kw in q for kw in ["summary", "overview", "overall"]):
            totals, overall = fuzz_summary(db_path)
            ok   = overall.get("ok", 0)
            fail = overall.get("expected_failure", 0)
            total = ok + fail
            lines = [f"Fuzzing Summary  ({total} total runs)"]
            current_stage = None
            for stage, status, cnt in totals:
                if stage != current_stage:
                    lines.append(f"\n  {stage}")
                    current_stage = stage
                tag = "✓" if status == "ok" else "✗"
                lines.append(f"    {tag}  {status:<22} {cnt} run(s)")
            lines.append(f"\n  Total: {ok}/{total} passed  |  {fail}/{total} failed")
            return "\n".join(lines)
 
        # failures
        if any(kw in q for kw in ["fail", "failure", "failures", "crash"]):
            rows = fuzz_failures(db_path)
            if not rows:
                return "No fuzzing failures found."
            lines = [f"Fuzzing Failures ({len(rows)} total):"]
            for stage, name, ch, tl, br, err in rows:
                lines.append(f"\n  Stage:  {stage}")
                lines.append(f"  Input:  {name or '—'}")
                lines.append(f"  Params: channel_cnt={ch}  times_len={tl}  beam_rows={br}")
                lines.append(f"  Error:  {err}")
            return "\n".join(lines)
 
        # risky
        if any(kw in q for kw in ["risky", "risk", "boundary", "out-of-range", "anomalous"]):
            rows = fuzz_risky_runs(db_path)
            if not rows:
                return "No risky passing runs found."
            lines = [f"Risky Passing Runs — out-of-range inputs that did NOT crash ({len(rows)} found):"]
            for stage, name, n_rows, ch, az, seed, status in rows:
                label = name or f"seed={seed}"
                flags = []
                if az and (az > 360 or az < 0):
                    flags.append(f"back_az={round(az, 2)} (out of [0,360])")
                if ch == 0:
                    flags.append("channel_cnt=0")
                if n_rows is not None and n_rows <= 1:
                    flags.append(f"n_rows={n_rows} (too small)")
                lines.append(f"  ✓  {stage:<25}  {label:<28}  ⚠ {', '.join(flags)}")
            return "\n".join(lines)
 
        # stage
        if fstage or any(kw in q for kw in ["stage", "runs for"]):
            target = fstage or ""
            rows = fuzz_runs_by_stage(db_path, target)
            if not rows:
                return f"No fuzzing runs found for stage '{target}'."
            lines = [f"Fuzzing runs for stage '{target}' ({len(rows)} total):"]
            for s, name, n_rows, ch, az, seed, status, err in rows:
                tag = "✓" if status == "ok" else "✗"
                label = name or f"seed={seed}"
                lines.append(f"  [{tag}]  {label:<30}  n_rows={str(n_rows or '—'):<6}  ch={ch}  az={round(az, 3) if az else 0}")
                if err:
                    lines.append(f"        ↳ {err}")
            return "\n".join(lines)
 
        # channel
        if fch is not None:
            rows = fuzz_runs_by_channel(db_path, fch)
            if not rows:
                return f"No fuzzing runs with channel_cnt = {fch}."
            lines = [f"Fuzzing runs with channel_cnt = {fch}  ({len(rows)} total):"]
            for stage, name, n_rows, ch, az, status, err in rows:
                tag = "✓" if status == "ok" else "✗"
                label = name or f"n_rows={n_rows}"
                lines.append(f"  [{tag}]  {stage:<25}  {label:<28}  az={round(az, 3) if az else 0}")
                if err:
                    lines.append(f"        ↳ {err}")
            return "\n".join(lines)
 
        # generic fuzz help
        return (
            "Fuzzing queries understood:\n"
            "  'fuzzing summary'             — pass/fail counts by stage\n"
            "  'show fuzzing failures'       — all failure runs + error messages\n"
            "  'fuzzing runs for run_fk'     — runs for a specific stage\n"
            "  'show risky fuzzing runs'     — passed runs with out-of-range inputs\n"
            "  'fuzzing channel 2'           — runs with a specific channel count"
        )

    #Call Graph Routes
    if any(kw in q for kw in ["caller of", "calls", "reach", "can reach", "does call"]):
        if len(funcs) >= 2:
            found, path = is_caller(forward, funcs[0], funcs[1])
            if found:
                return(f"Yes - {funcs[0]} is a caller of {funcs[1]}\n"
                       f"Path: {' -> '.join(path)}")
            else:
                return f"No - {funcs[0]} cannot reach {funcs[1]}"
        elif len(funcs) == 1:
            return f"Found one function ({funcs[0]}) but need two to check reachability. Please name both"
    if any(kw in q for kw in ["path from", "shortest path", "call chain", "path to"]):
          if len(funcs) >= 2:
            found, path = is_caller(forward, funcs[0], funcs[1])
            if found:
                return f"Shortest path:\n  {' → '.join(path)}"
            else:
                return f"No path found from {funcs[0]} to {funcs[1]}"
    if any(kw in q for kw in ["what does", "directly call", "calls directly"]):
        if funcs:
            results = direct_callees(forward, funcs[0])
            if results:
                 return f"{funcs[0]} directly calls:\n" + "\n".join(f"  • {r}" for r in results)
            return f"{funcs[0]} does not call any known functions directly."    
    if any (kw in q for kw in ["who calls", "what calls", "directly called by"]):
        if funcs:
            results = direct_callers(reverse, funcs[0])
            if results:
                return f"Functions that directly call {funcs[0]}:\n" + "\n".join(f"  • {r}" for r in results)
            return f"No known functions call {funcs[0]} directly."    
    if any(kw in q for kw in ["can reach", "all callees", "reachable from", "what functions does"]):
        if funcs:
            results = all_callees(forward, funcs[0])
            if results:
                return (f"All functions reachable from {funcs[0]} ({len(results)} total):\n"
                        + "\n".join(f"  • {r}" for r in results))
            return f"{funcs[0]} cannot reach any other known functions."  
    if any(kw in q for kw in ["all callers", "functions call", "what functions call"]):
        if funcs:
            results = all_callers(reverse, funcs[0])
            if results:
                return (f"All functions that call {funcs[0]} ({len(results)} total):\n"
                        + "\n".join(f"  • {r}" for r in results))
            return f"No known functions call {funcs[0]}."
        
    #Coverage Routes
    if any(kw in q for kw in ["summary", "overall coverage", "all files"]):
        results = overall_summary(db_path)
        lines = ["Coverage Summary:"]
        for f, covered, total, pct in results:
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            lines.append(f"  {f:<30} [{bar}] {pct}%  ({covered}/{total})")
        return "\n".join(lines)
    if any(kw in q for kw in ["coverage of", "branch coverage", "how covered", "coverage for"]):
        if file:
            covered, total, pct, uncovered = branch_coverage(db_path, file)
            if covered is None:
                return f"No coverage data found for {file}."
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            result = (f"Branch coverage for {file}:\n"
                      f"  [{bar}] {pct}%  ({covered}/{total} branches)\n")
            if uncovered:
                result += f"  First 10 uncovered branches:\n"
                for line, branch in uncovered[:10]:
                    result += f"    line {line}  branch {branch}\n"
                if len(uncovered) > 10:
                    result += f"    ... and {len(uncovered) - 10} more"
            return result.strip()
        return "Please name a file. Known files: " + ", ".join(KNOWN_FILES)
    if any(kw in q for kw in ["uncovered lines", "uncovered in", "not covered", "missing coverage"]):
        if file:
            lines = uncovered_lines(db_path, file)
            if not lines:
                return f"No uncovered lines in {file} — full coverage!"
            result = f"Uncovered lines in {file} ({len(lines)} total):\n  "
            result += "  ".join(str(l) for l in lines[:30])
            if len(lines) > 30:
                result += f"\n  ... and {len(lines) - 30} more"
            return result
        return "Please name a file. Known files: " + ", ".join(KNOWN_FILES)
    if any(kw in q for kw in ["compare", "test runs", "across runs", "per run"]):
        if file:
            results = compare_test_runs(db_path, file)
            if not results:
                return f"No test run data found for {file}."
            lines = [f"Coverage comparison for {file}:"]
            for run_id, covered, total, pct in results:
                bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
                lines.append(f"  {run_id}:\n  [{bar}] {pct}%  ({covered}/{total})")
            return "\n".join(lines)
        return "Please name a file. Known files: " + ", ".join(KNOWN_FILES)
    if any(kw in q for kw in ["dependent", "data-dependent", "share", "related"]):
        if len(vars_) >= 2:
            shared = are_dependent(db_path, vars_[0], vars_[1])
            if shared:
                return (f"YES — '{vars_[0]}' and '{vars_[1]}' are data-dependent.\n"
                        f"Both appear in:\n" + "\n".join(f"  • {f}" for f in shared))
            return f"NO — '{vars_[0]}' and '{vars_[1]}' share no common functions."
        elif len(vars_) == 1:
            return f"Found one variable ({vars_[0]}) but need two to check dependency. Please name both."
    if any(kw in q for kw in ["where is", "used", "dataflow", "trace", "defined", "variable"]):
        if vars_:
            rows = dataflow_lookup(db_path, vars_[0])
            if not rows:
                return f"No dataflow data found for variable '{vars_[0]}'."
            import json
            lines = [f"Dataflow for '{vars_[0]}' ({len(rows)} events):"]
            for caller, callee, file, line, extra in rows:
                kind = json.loads(extra).get("kind", "?") if extra else "?"
                ctx  = json.loads(extra).get("context", "") if extra else ""
                lines.append(f"  line {str(line):>5}  [{kind:<10}]  in {callee:<25}  {ctx}")
            return "\n".join(lines)
    
    return (
        "Sorry, I couldn't understand that query. Try one of these patterns:\n"
        "  Call graph:  'Is X a caller of Y?'  |  'What does X call?'  |  'Who calls X?'\n"
        "               'What can X reach?'    |  'What is the path from X to Y?'\n"
        "  Coverage:    'What is the coverage of beamforming_new.py?'\n"
        "               'What lines are uncovered in spectral.py?'\n"
        "               'Show coverage summary'\n"
        "  Dataflow:    'Where is thresh used?'\n"
        "               'Are thresh and det_mask data-dependent?'"
        "  Fuzzing:     'Show fuzzing summary'\n"
        "               'Show fuzzing failures'\n"
        "               'Show fuzzing runs for run_fk'\n"
        "               'Show risky fuzzing runs'\n"
        "                'Fuzzing channel 2'"
    )
 

#
# Interactive Shell
#
def interactive_shell(db_path):
    forward, reverse = load_call_graph(db_path)
 
    print("\n========================================")
    print("  InfraPy Natural Language Query Router")
    print("========================================")
    print("Ask questions in plain English. Examples:")
    print("  Is detect_signals a caller of calc_det_thresh?")
    print("  What does run_fk call?")
    print("  What is the coverage of beamforming_new.py?")
    print("  What lines are uncovered in spectral.py?")
    print("  Where is thresh used?")
    print("  Are thresh and det_mask data-dependent?")
    print("  Show coverage summary")
    print("  Show fuzzing summary")
    print("  Show fuzzing failures")
    print("  Show fuzzing runs for run_fk")
    print("  Show risky fuzzing runs")
    print("\nType 'quit' to exit.")
    print("========================================\n")
 
    while True:
        try:
            question = input("ask> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
 
        if not question:
            continue
        if question.lower() == "quit":
            break
 
        result = router(db_path, forward, reverse, question)
        print(f"\n{result}\n")
 

#
#   CLI Entry Point
#

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="InfraPy Natural Language Query Router")
    parser.add_argument("--db", default="413db.db", help="Path to SQLite database")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive shell")
    parser.add_argument("--ask", help="Ask a single natural language question")
    args = parser.parse_args()

    if args.ask:
        forward, reverse = load_call_graph(args.db)
        print(router(args.db, forward, reverse, args.ask))
    else:
        interactive_shell(args.db)
    

        
