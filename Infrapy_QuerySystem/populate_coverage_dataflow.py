import sqlite3, json

DB = "413db.db"
conn = sqlite3.connect(DB)

conn.execute("""
    CREATE TABLE IF NOT EXISTS coverage (
        id          INTEGER PRIMARY KEY,
        test_run_id TEXT,
        file        TEXT,
        line_number INTEGER,
        branch_id   TEXT,
        covered     INTEGER
    )
""")


# dataflow table (adds to existing static_analysis table)

with open("coverage.json") as f:
    cov = json.load(f)

conn.executemany("""
    INSERT INTO coverage (test_run_id, file, line_number, branch_id, covered)
                 VALUES (:test_run_id, :file, :line_number, :branch_id, :covered)
""", cov["coverage_rows"])

print(f"Inserted {len(cov['coverage_rows'])} coverage rows")

# Insert dataflow rows into static_analysis
with open("dataflow.json") as f:
    dataflow_data = json.load(f)

conn.executemany("""
    INSERT INTO static_analysis (analysis_type, caller, callee, file, line_number, extra_data)
    VALUES (:analysis_type, :caller, :callee, :file, :line_number, :extra_data)
""", dataflow_data["static_analysis_rows"])

print(f"Inserted {len(dataflow_data['static_analysis_rows'])} dataflow rows")

conn.commit()
conn.close()
print("ALL DONE!")