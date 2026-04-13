#!/usr/bin/env python3
"""
sqlite_to_postgres.py - v3.0 Migration Script
Migrate SQLite baseline.db to Postgres (one-time run).
Robust error handling and batch inserts.
"""

import sqlite3
import psycopg2
import configparser
from pathlib import Path

def migrate():
    # Load config (Postgres connection details)
    parser = configparser.ConfigParser()
    parser.read(['config.ini', 'v3.0/config.ini', '/app/config.ini'])

    postgres_conn_params = {
        "dbname": parser.get('postgres', 'dbname', fallback='c2_beacon_hunter'),
        "user": parser.get('postgres', 'user', fallback='user'),
        "password": parser.get('postgres', 'password', fallback='password'),
        "host": parser.get('postgres', 'host', fallback='localhost'),
        "port": parser.get('postgres', 'port', fallback=5432)
    }

    sqlite_db = Path("data/baseline.db")

    try:
        sqlite_conn = sqlite3.connect(sqlite_db)
        sqlite_cursor = sqlite_conn.cursor()

        postgres_conn = psycopg2.connect(**postgres_conn_params)
        postgres_cursor = postgres_conn.cursor()

        # Create table in Postgres if not exists
        postgres_cursor.execute("""
            CREATE TABLE IF NOT EXISTS flows (
                id SERIAL PRIMARY KEY,
                timestamp DOUBLE PRECISION,
                process_name TEXT,
                dst_ip TEXT,
                interval DOUBLE PRECISION,
                cv DOUBLE PRECISION,
                outbound_ratio DOUBLE PRECISION,
                entropy DOUBLE PRECISION,
                packet_size_mean DOUBLE PRECISION,
                packet_size_std DOUBLE PRECISION,
                packet_size_min DOUBLE PRECISION,
                packet_size_max DOUBLE PRECISION,
                mitre_tactic TEXT,
                pid INTEGER,
                cmd_entropy DOUBLE PRECISION,
                suppressed INTEGER DEFAULT 0
            )
        """)
        postgres_conn.commit()

        # Batch migrate data
        sqlite_cursor.execute("SELECT * FROM flows")
        rows = sqlite_cursor.fetchall()
        batch_size = 200
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i+batch_size]
            postgres_cursor.executemany("""
                INSERT INTO flows (timestamp, process_name, dst_ip, interval, cv, outbound_ratio, entropy,
                                   packet_size_mean, packet_size_std, packet_size_min, packet_size_max,
                                   mitre_tactic, pid, cmd_entropy, suppressed)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, batch)
            postgres_conn.commit()
            print(f"Migrated {len(batch)} rows ({i+len(batch)} total)")

        print("Migration complete. SQLite data transferred to Postgres.")

    except Exception as e:
        print(f"[ERROR] Migration failed: {e}")
    finally:
        if 'sqlite_conn' in locals():
            sqlite_conn.close()
        if 'postgres_conn' in locals():
            postgres_conn.close()

if __name__ == "__main__":
    migrate()