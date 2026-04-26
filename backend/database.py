"""
database.py — SQLite database layer
Zero config, single file, handles 20 concurrent users easily.
"""
import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "s1assistant.db")

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS query_library (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        category TEXT NOT NULL,
        platform TEXT DEFAULT 'All',
        mitre TEXT DEFAULT '[]',
        query TEXT NOT NULL,
        tier TEXT DEFAULT 'silver',
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS query_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_hash TEXT NOT NULL,
        input_text TEXT NOT NULL,
        input_type TEXT NOT NULL,
        query_text TEXT NOT NULL,
        star_rule TEXT,
        intent_json TEXT,
        severity TEXT DEFAULT 'MEDIUM',
        confidence REAL DEFAULT 0.0,
        validation_status TEXT DEFAULT 'PASS',
        validation_warnings TEXT DEFAULT '[]',
        explanation TEXT,
        mitre TEXT DEFAULT '[]',
        notes TEXT DEFAULT '[]',
        ioc_summary TEXT,
        analyst_id TEXT DEFAULT 'default',
        source TEXT DEFAULT 'manual',
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS threat_feeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT NOT NULL,
        severity TEXT DEFAULT 'HIGH',
        title TEXT NOT NULL,
        description TEXT,
        malware_family TEXT,
        mitre TEXT DEFAULT '[]',
        iocs_json TEXT DEFAULT '{}',
        precompiled_query TEXT,
        fetched_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT
    );

    CREATE TABLE IF NOT EXISTS analyst_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_hash TEXT NOT NULL,
        analyst_id TEXT DEFAULT 'default',
        verdict TEXT NOT NULL,
        suppressions_added TEXT DEFAULT '[]',
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS suppressions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scope TEXT DEFAULT 'global',
        suppression_type TEXT NOT NULL,
        value TEXT NOT NULL,
        created_by TEXT DEFAULT 'system',
        expires_at TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );


    CREATE TABLE IF NOT EXISTS hunt_packs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_hash TEXT NOT NULL,
        input_text TEXT NOT NULL,
        primary_hunt_json TEXT,
        supporting_hunts_json TEXT,
        analysis_json TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_history_hash ON query_history(query_hash);
    CREATE INDEX IF NOT EXISTS idx_history_created ON query_history(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_history_analyst ON query_history(analyst_id);
    CREATE INDEX IF NOT EXISTS idx_feeds_source ON threat_feeds(source);
    CREATE INDEX IF NOT EXISTS idx_feeds_fetched ON threat_feeds(fetched_at DESC);
    CREATE INDEX IF NOT EXISTS idx_feedback_hash ON analyst_feedback(query_hash);
    CREATE INDEX IF NOT EXISTS idx_library_category ON query_library(category);
    CREATE INDEX IF NOT EXISTS idx_hunt_packs_hash ON hunt_packs(query_hash);
    CREATE INDEX IF NOT EXISTS idx_hunt_packs_created ON hunt_packs(created_at DESC);
    """)
    conn.commit()
    conn.close()
