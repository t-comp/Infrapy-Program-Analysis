import sqlite3, json

DB = "413db.db"

with open("coverage_update.json") as f:
    data = json.load(f)

conn = sqlite3.connect(DB)

conn.executemany("""
    INSERT INTO coverage (test_run_id, file, line_number, branch_id, covered)
    VALUES (:test_run_id, :file, :line_number, :branch_id, :covered)
""", data["coverage_rows"])

conn.commit()
conn.close()
print(f"Inserted {len(data['coverage_rows'])} rows for beamforming_new.py")