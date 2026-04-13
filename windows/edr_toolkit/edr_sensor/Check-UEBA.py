import sqlite3
import os

db_path = r"C:\ProgramData\DeepSensor\Data\DeepSensor_UEBA.db"

if not os.path.exists(db_path):
    print(f"[!] Database not found at {db_path}")
    exit()

print(f"[*] Found Database: {db_path}")
print(f"[*] File Size: {os.path.getsize(db_path) / 1024:.2f} KB\n")

try:
    # Connect in read-only mode so we don't lock the DB while the sensor is running
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cursor = conn.cursor()

    # 1. Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()

    if not tables:
        print("[-] Database exists, but no tables have been created yet.")
    else:
        print("=== DATABASE CONTENTS ===")
        for table_name in tables:
            name = table_name[0]
            # 2. Count rows in each table
            cursor.execute(f"SELECT COUNT(*) FROM {name}")
            count = cursor.fetchone()[0]
            print(f" -> Table '{name}': {count} rows recorded.")

            # Optional: Print the last 3 rows of the table to verify the data
            if count > 0:
                print("    [Latest Entries]:")
                cursor.execute(f"SELECT * FROM {name} ORDER BY rowid DESC LIMIT 3")
                for row in cursor.fetchall():
                    print(f"      {row}")
            print()

except sqlite3.OperationalError as e:
    print(f"[!] SQLite Error: {e}")
    print("[!] Are you running this as Administrator? The folder is locked by icacls.")
finally:
    if 'conn' in locals():
        conn.close()