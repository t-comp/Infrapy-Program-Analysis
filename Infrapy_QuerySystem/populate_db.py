import sqlite3, json

DB = "413db.db"

with open("call.json") as f:
    call_data = json.load(f)

with open("cfg.json") as f:
    cfg_data = json.load(f)

conn = sqlite3.connect(DB)

conn.executemany("""
    INSERT INTO static_analysis (analysis_type, caller, callee, file, line_number, extra_data)
    VALUES (:analysis_type, :caller, :callee, :file, :line_number, :extra_data)
""", call_data["static_analysis_rows"])

conn.executemany("""
INSERT INTO static_analysis (analysis_type, caller, callee, file, line_number, extra_data)
    VALUES (:analysis_type, :caller, :callee, :file, :line_number, :extra_data)
""", cfg_data["static_analysis_rows"])

conn.executemany("""
 INSERT INTO metadata (function_name, file, input_range_notes)
    VALUES (:function_name, :file, :input_range_notes)
""", [
    {
        "function_name": r["function_name"],
        "file": r["file"],
        "input_range_notes": f"lines {r['start_line']}–{r['end_line']} ({r['line_count']} lines)"
    }
    for r in call_data["metadata_rows"]
])

conn.commit()
conn.close()

print(f"Inserted {len(call_data['static_analysis_rows'])} call graph edges")
print(f"Inserted {len(cfg_data['static_analysis_rows'])} CFG edges")
print(f"Inserted {len(call_data['metadata_rows'])} metadata rows")