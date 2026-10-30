import sqlite3
import json
from pathlib import Path
import pandas as pd

DB_PATH = Path(__file__).resolve().parent / "phishguard.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            input_type TEXT NOT NULL,
            content TEXT NOT NULL,
            risk_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            warnings TEXT NOT NULL
        )
        """)
        conn.commit()

def save_analysis(input_type, content, score, verdict, warnings):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO analyses(timestamp,input_type,content,risk_score,verdict,warnings) VALUES(?,?,?,?,?,?)",
            (pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S"), input_type, content[:5000], float(score), verdict, json.dumps(warnings))
        )
        conn.commit()

def get_history():
    with sqlite3.connect(DB_PATH) as conn:
        df = pd.read_sql_query(
            "SELECT id,timestamp,input_type,content,risk_score,verdict,warnings FROM analyses ORDER BY id DESC LIMIT 500",
            conn
        )
    if not df.empty:
        df["warnings"] = df["warnings"].apply(lambda v: ", ".join(json.loads(v)) if v else "")
        df["risk_score"] = df["risk_score"].astype(float)
    return df

def clear_history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM analyses")
        conn.commit()
