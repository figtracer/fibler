import sqlite3
import json
from datetime import datetime


class BinaryDatabase:
    def __init__(self):
        self.db_path = "fibler.db"
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS binary_analysis (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT UNIQUE,
                    architecture TEXT,
                    file_type TEXT,
                    endianness TEXT,
                    va TEXT,
                    vt_total INTEGER,
                    vt_positives INTEGER,
                    analysis_date TIMESTAMP,
                    sections TEXT,  -- JSON string
                    imports TEXT,   -- JSON string
                    exports TEXT    -- JSON string
                )
            """
            )

    def store_analysis(self, file_path: str, binary_info: dict):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    """
                    SELECT id FROM binary_analysis 
                    WHERE file_path = ?
                """,
                    (file_path,),
                )

                if cursor.fetchone() is None:  # only insert if not found
                    conn.execute(
                        """
                        INSERT INTO binary_analysis (
                            file_path, architecture, file_type, endianness,
                            va, vt_total, vt_positives, analysis_date,
                            sections, imports, exports
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                        (
                            file_path,
                            binary_info.get("architecture", ""),
                            binary_info.get("file_type", ""),
                            binary_info.get("endianness", ""),
                            hex(binary_info.get("va", 0)),
                            binary_info.get("total", 0),
                            binary_info.get("positives", 0),
                            datetime.now().isoformat(),
                            json.dumps(
                                [str(s) for s in binary_info.get("sections", [])]
                            ),
                            json.dumps(binary_info.get("imports", [])),
                            json.dumps(binary_info.get("exports", [])),
                        ),
                    )
                    print(f"Stored new analysis for {file_path}")
                else:
                    print(f"Analysis already exists for {file_path}")
        except Exception as e:
            print(f"Error storing analysis: {e}")
