import sqlite3, json

DB = "413db.db"

with open("fuzz_results.json") as f:
    data = json.load(f)

conn = sqlite3.connect(DB)

rows = []
for r in data:
    inp = r["inputs"]
    rows.append((
        r["stage"],
        inp.get("name"),
        inp.get("times_len"),
        inp.get("beam_shape", [None, None])[0],
        inp.get("beam_shape", [None, None])[1],
        inp.get("channel_cnt"),
        inp.get("back_az_lim"),
        inp.get("n_rows"),
        inp.get("seed"),
        r["status"],
        r["error"]
    ))

conn.executemany("""
    INSERT INTO fuzzing (stage, input_name, times_len, beam_rows, beam_cols,
                         channel_cnt, back_az_lim, n_rows, seed, status, error)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
""", rows)

conn.commit()
conn.close()
print(f"Inserted {len(rows)} fuzzing runs")