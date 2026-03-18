"""SQLite database for caching, undo history, stats, and sender decisions."""

import json
import os
import sqlite3
import threading
import time
from collections import defaultdict

from inboxdna.paths import USER_DATA_DIR

DATA_DIR = USER_DATA_DIR
DB_PATH = os.path.join(DATA_DIR, "email_organizer.db")
STATS_JSON = os.path.join(DATA_DIR, "stats.json")

_local = threading.local()


def get_db():
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
        _local.conn.execute("PRAGMA busy_timeout=5000")
    return _local.conn


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            from_name TEXT NOT NULL,
            from_email TEXT NOT NULL,
            subject TEXT,
            snippet TEXT,
            date_str TEXT,
            epoch INTEGER DEFAULT 0,
            unread INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Other',
            spam_score INTEGER DEFAULT 0,
            has_unsubscribe INTEGER DEFAULT 0,
            size INTEGER DEFAULT 0,
            fetched_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_email ON messages(from_email);
        CREATE INDEX IF NOT EXISTS idx_messages_epoch ON messages(epoch);

        CREATE TABLE IF NOT EXISTS undo_stack (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            sender TEXT,
            filter_id TEXT,
            message_ids TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sender_decisions (
            sender_email TEXT PRIMARY KEY,
            decision TEXT NOT NULL,
            filter_id TEXT,
            decided_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS stats (
            key TEXT PRIMARY KEY,
            value INTEGER DEFAULT 0
        );


        CREATE TABLE IF NOT EXISTS scan_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            total_messages INTEGER NOT NULL,
            total_unread INTEGER NOT NULL,
            total_senders INTEGER NOT NULL,
            total_size INTEGER NOT NULL,
            marketing_count INTEGER DEFAULT 0,
            human_count INTEGER DEFAULT 0,
            scanned_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sender_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_id INTEGER NOT NULL,
            from_email TEXT NOT NULL,
            from_name TEXT,
            message_count INTEGER DEFAULT 0,
            unread_count INTEGER DEFAULT 0,
            read_rate INTEGER DEFAULT 0,
            total_size INTEGER DEFAULT 0,
            spam_score INTEGER DEFAULT 0,
            has_unsubscribe INTEGER DEFAULT 0,
            category TEXT DEFAULT 'Other',
            newest_epoch INTEGER DEFAULT 0,
            oldest_epoch INTEGER DEFAULT 0,
            recorded_at INTEGER DEFAULT 0,
            FOREIGN KEY (snapshot_id) REFERENCES scan_snapshots(id)
        );
        CREATE INDEX IF NOT EXISTS idx_sender_history_email ON sender_history(from_email);
        CREATE INDEX IF NOT EXISTS idx_sender_history_snapshot ON sender_history(snapshot_id);

        CREATE TABLE IF NOT EXISTS hygiene_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            score INTEGER NOT NULL,
            unread_ratio REAL,
            sub_to_human_ratio REAL,
            avg_email_age_days REAL,
            storage_efficiency REAL,
            actions_taken_score REAL,
            computed_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS hygiene_badges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            badge_key TEXT UNIQUE NOT NULL,
            badge_label TEXT NOT NULL,
            badge_icon TEXT DEFAULT '',
            earned_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sent_messages_cache (
            id TEXT PRIMARY KEY,
            to_email TEXT NOT NULL,
            subject TEXT,
            epoch INTEGER DEFAULT 0,
            fetched_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_sent_to ON sent_messages_cache(to_email);

        CREATE TABLE IF NOT EXISTS sender_profiles (
            sender_email TEXT PRIMARY KEY,
            display_name TEXT,
            avg_frequency_per_week REAL,
            avg_message_size INTEGER,
            tracking_pixel_count INTEGER DEFAULT 0,
            frequency_trend TEXT,
            respect_score INTEGER DEFAULT 50,
            dark_patterns TEXT,
            profile_data TEXT,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS privacy_audit_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT NOT NULL,
            sender_email TEXT NOT NULL,
            finding_type TEXT NOT NULL,
            finding_detail TEXT,
            severity TEXT DEFAULT 'medium',
            audited_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_privacy_sender ON privacy_audit_results(sender_email);
        CREATE INDEX IF NOT EXISTS idx_privacy_type ON privacy_audit_results(finding_type);

        CREATE TABLE IF NOT EXISTS triage_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT NOT NULL,
            sender_name TEXT,
            action TEXT NOT NULL,
            source TEXT DEFAULT 'triage',
            message_count INTEGER DEFAULT 0,
            acted_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_triage_actions_email ON triage_actions(sender_email);

        CREATE TABLE IF NOT EXISTS ghost_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_email TEXT,
            domain TEXT,
            suggested_action TEXT NOT NULL,
            confidence REAL NOT NULL,
            pattern_description TEXT,
            consecutive_count INTEGER,
            status TEXT DEFAULT 'pending',
            created_at INTEGER NOT NULL
        );
    """)
    # Seed stats rows
    for key in ("emails_cleaned", "co2_saved_grams", "storage_freed_bytes"):
        db.execute("INSERT OR IGNORE INTO stats (key, value) VALUES (?, 0)", (key,))
    db.commit()

    # Migrations
    _migrate_stats_json()
    _migrate_add_recorded_at()


def _migrate_stats_json():
    if not os.path.exists(STATS_JSON):
        return
    db = get_db()
    # Only migrate if all stats are still 0
    row = db.execute("SELECT SUM(value) as total FROM stats").fetchone()
    if row["total"] and row["total"] > 0:
        return
    try:
        with open(STATS_JSON, "r") as f:
            data = json.load(f)
        for key in ("emails_cleaned", "co2_saved_grams", "storage_freed_bytes"):
            if data.get(key, 0) > 0:
                db.execute("UPDATE stats SET value = ? WHERE key = ?", (data[key], key))
        db.commit()
    except Exception:
        pass


def _migrate_add_recorded_at():
    """Add recorded_at column to sender_history if missing (schema fix)."""
    db = get_db()
    try:
        db.execute("SELECT recorded_at FROM sender_history LIMIT 1")
    except Exception:
        try:
            db.execute("ALTER TABLE sender_history ADD COLUMN recorded_at INTEGER DEFAULT 0")
            db.commit()
        except Exception:
            pass


# --- Messages cache ---

def get_cached_message_ids():
    db = get_db()
    rows = db.execute("SELECT id FROM messages").fetchall()
    return {r["id"] for r in rows}


def upsert_messages(messages):
    if not messages:
        return
    db = get_db()
    now = int(time.time())
    db.executemany(
        """INSERT OR REPLACE INTO messages
           (id, from_name, from_email, subject, snippet, date_str, epoch,
            unread, category, spam_score, has_unsubscribe, size, fetched_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [(m["id"], m["from_name"], m["from_email"], m["subject"], m["snippet"],
          m["date"], m["epoch"], int(m["unread"]), m["category"], m["spam_score"],
          int(m["has_unsubscribe"]), m["size"], now) for m in messages]
    )
    db.commit()


def get_cached_messages(id_set):
    """Return cached messages for the given IDs, grouped by from_email."""
    if not id_set:
        return {}
    db = get_db()
    senders = defaultdict(list)
    # Query in chunks to avoid SQLite variable limit
    id_list = list(id_set)
    for i in range(0, len(id_list), 900):
        chunk = id_list[i:i + 900]
        placeholders = ",".join("?" * len(chunk))
        rows = db.execute(
            f"SELECT * FROM messages WHERE id IN ({placeholders})", chunk
        ).fetchall()
        for r in rows:
            senders[r["from_email"]].append({
                "id": r["id"],
                "from_name": r["from_name"],
                "from_email": r["from_email"],
                "subject": r["subject"],
                "snippet": r["snippet"],
                "date": r["date_str"],
                "epoch": r["epoch"],
                "unread": bool(r["unread"]),
                "category": r["category"],
                "spam_score": r["spam_score"],
                "has_unsubscribe": bool(r["has_unsubscribe"]),
                "size": r["size"],
            })
    return dict(senders)


def get_sender_aggregates(id_set):
    """Return per-sender aggregates using SQL GROUP BY.
    Avoids materializing all messages into Python dicts."""
    if not id_set:
        return []
    db = get_db()
    results = []
    id_list = list(id_set)
    for i in range(0, len(id_list), 900):
        chunk = id_list[i:i + 900]
        placeholders = ",".join("?" * len(chunk))
        rows = db.execute(f"""
            SELECT from_email,
                   from_name,
                   COUNT(*) AS count,
                   SUM(CASE WHEN unread = 1 THEN 1 ELSE 0 END) AS unread,
                   ROUND(AVG(spam_score)) AS avg_spam,
                   MAX(has_unsubscribe) AS has_unsub,
                   SUM(size) AS total_size,
                   MIN(epoch) AS oldest_epoch,
                   MAX(epoch) AS newest_epoch,
                   category
            FROM messages
            WHERE id IN ({placeholders})
            GROUP BY from_email
        """, chunk).fetchall()
        results.extend(rows)
    # Merge results across chunks (same sender could span chunks)
    merged = defaultdict(lambda: {
        "from_name": "", "count": 0, "unread": 0, "spam_total": 0,
        "has_unsub": 0, "total_size": 0, "oldest_epoch": float("inf"),
        "newest_epoch": 0, "categories": defaultdict(int),
    })
    for r in results:
        email = r["from_email"]
        m = merged[email]
        m["from_name"] = r["from_name"]
        m["count"] += r["count"]
        m["unread"] += r["unread"]
        m["spam_total"] += r["avg_spam"] * r["count"]
        m["has_unsub"] = max(m["has_unsub"], r["has_unsub"])
        m["total_size"] += r["total_size"]
        m["oldest_epoch"] = min(m["oldest_epoch"], r["oldest_epoch"])
        m["newest_epoch"] = max(m["newest_epoch"], r["newest_epoch"])
        m["categories"][r["category"]] += r["count"]
    sender_list = []
    for email, m in merged.items():
        total = m["count"]
        read = total - m["unread"]
        top_cat = max(m["categories"], key=m["categories"].get) if m["categories"] else "Other"
        sender_list.append({
            "email": email,
            "name": m["from_name"],
            "count": total,
            "unread": m["unread"],
            "read_rate": round(read / total * 100) if total > 0 else 0,
            "category": top_cat,
            "spam_score": round(m["spam_total"] / total) if total > 0 else 0,
            "has_unsubscribe": bool(m["has_unsub"]),
            "total_size": m["total_size"],
            "oldest_epoch": m["oldest_epoch"] if m["oldest_epoch"] != float("inf") else 0,
            "newest_epoch": m["newest_epoch"],
        })
    return sender_list


def get_message_ids_for_sender(sender_email):
    """Return message IDs for a given sender (lightweight query for actions)."""
    db = get_db()
    rows = db.execute(
        "SELECT id FROM messages WHERE from_email = ?", (sender_email,)
    ).fetchall()
    return [r["id"] for r in rows]


def get_cached_messages_for_sender(sender_email):
    """Return all cached messages for a given sender email."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM messages WHERE from_email = ? ORDER BY epoch DESC", (sender_email,)
    ).fetchall()
    return [{
        "id": r["id"],
        "from_name": r["from_name"],
        "from_email": r["from_email"],
        "subject": r["subject"],
        "snippet": r["snippet"],
        "date": r["date_str"],
        "epoch": r["epoch"],
        "unread": bool(r["unread"]),
        "category": r["category"],
        "spam_score": r["spam_score"],
        "has_unsubscribe": bool(r["has_unsubscribe"]),
        "size": r["size"],
    } for r in rows]


def delete_messages(id_list):
    if not id_list:
        return
    db = get_db()
    ids = list(id_list)
    for i in range(0, len(ids), 900):
        chunk = ids[i:i + 900]
        placeholders = ",".join("?" * len(chunk))
        db.execute(f"DELETE FROM messages WHERE id IN ({placeholders})", chunk)
    db.commit()


def clear_all_messages():
    db = get_db()
    db.execute("DELETE FROM messages")
    db.commit()


def close_db():
    """Close the current thread's database connection."""
    if hasattr(_local, "conn") and _local.conn is not None:
        _local.conn.close()
        _local.conn = None


# --- Undo stack ---

def push_undo(action, message_ids, sender=None, filter_id=None):
    db = get_db()
    db.execute(
        "INSERT INTO undo_stack (action, sender, filter_id, message_ids, created_at) VALUES (?, ?, ?, ?, ?)",
        (action, sender, filter_id, json.dumps(message_ids), int(time.time()))
    )
    # Prune old entries beyond the most recent 50
    db.execute("""
        DELETE FROM undo_stack WHERE id NOT IN (
            SELECT id FROM undo_stack ORDER BY id DESC LIMIT 50
        )
    """)
    db.commit()


def pop_undo():
    db = get_db()
    row = db.execute("SELECT * FROM undo_stack ORDER BY id DESC LIMIT 1").fetchone()
    if row is None:
        return None
    db.execute("DELETE FROM undo_stack WHERE id = ?", (row["id"],))
    db.commit()
    return {
        "action": row["action"],
        "sender": row["sender"],
        "filter_id": row["filter_id"],
        "message_ids": json.loads(row["message_ids"]),
    }


def undo_count():
    db = get_db()
    row = db.execute("SELECT COUNT(*) as cnt FROM undo_stack").fetchone()
    return row["cnt"]


# --- Sender decisions ---

def record_decision(sender_email, decision, filter_id=None):
    db = get_db()
    db.execute(
        "INSERT OR REPLACE INTO sender_decisions (sender_email, decision, filter_id, decided_at) VALUES (?, ?, ?, ?)",
        (sender_email, decision, filter_id, int(time.time()))
    )
    db.commit()


def remove_decision(sender_email):
    db = get_db()
    db.execute("DELETE FROM sender_decisions WHERE sender_email = ?", (sender_email,))
    db.commit()


def get_decisions():
    db = get_db()
    rows = db.execute("SELECT * FROM sender_decisions").fetchall()
    return {r["sender_email"]: {"decision": r["decision"], "filter_id": r["filter_id"],
                                 "decided_at": r["decided_at"]} for r in rows}


# --- Stats ---

def load_stats():
    db = get_db()
    rows = db.execute("SELECT key, value FROM stats").fetchall()
    return {r["key"]: r["value"] for r in rows}


def increment_stats(count, size_bytes=0):
    db = get_db()
    db.execute("UPDATE stats SET value = value + ? WHERE key = 'emails_cleaned'", (count,))
    db.execute("UPDATE stats SET value = value + ? WHERE key = 'co2_saved_grams'", (count * 10,))
    db.execute("UPDATE stats SET value = value + ? WHERE key = 'storage_freed_bytes'", (size_bytes,))
    db.commit()
    return load_stats()


# --- Scan snapshots (Feature 6: Time Machine) ---

def save_scan_snapshot(total, unread, senders_count, total_size, marketing_count=0, human_count=0):
    """Save a snapshot of the current scan. Returns snapshot ID."""
    db = get_db()
    # Don't save duplicate snapshots within 5 minutes
    recent = db.execute(
        "SELECT id FROM scan_snapshots WHERE scanned_at > ?",
        (int(time.time()) - 300,)
    ).fetchone()
    if recent:
        return recent["id"]
    cur = db.execute(
        """INSERT INTO scan_snapshots
           (total_messages, total_unread, total_senders, total_size, marketing_count, human_count, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (total, unread, senders_count, total_size, marketing_count, human_count, int(time.time()))
    )
    db.commit()
    return cur.lastrowid


def save_sender_history(snapshot_id, sender_list):
    """Bulk insert sender metrics for a snapshot."""
    if not sender_list:
        return
    db = get_db()
    now = int(time.time())
    db.executemany(
        """INSERT INTO sender_history
           (snapshot_id, from_email, from_name, message_count, unread_count, read_rate,
            total_size, spam_score, has_unsubscribe, category, newest_epoch, oldest_epoch, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [(snapshot_id, s["email"], s["name"], s["count"], s["unread"], s["read_rate"],
          s["total_size"], s["spam_score"], int(s.get("has_unsubscribe", False)),
          s.get("category", "Other"), s.get("newest_epoch", 0), s.get("oldest_epoch", 0), now)
         for s in sender_list]
    )
    db.commit()


def get_snapshots(limit=52):
    """Return recent scan snapshots for charting."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM scan_snapshots ORDER BY scanned_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_growth_rate():
    """Compare latest snapshot to 1 week ago and 1 month ago."""
    db = get_db()
    now = int(time.time())
    latest = db.execute("SELECT * FROM scan_snapshots ORDER BY scanned_at DESC LIMIT 1").fetchone()
    if not latest:
        return None
    week_ago = db.execute(
        "SELECT * FROM scan_snapshots WHERE scanned_at <= ? ORDER BY scanned_at DESC LIMIT 1",
        (now - 7 * 86400,)
    ).fetchone()
    month_ago = db.execute(
        "SELECT * FROM scan_snapshots WHERE scanned_at <= ? ORDER BY scanned_at DESC LIMIT 1",
        (now - 30 * 86400,)
    ).fetchone()
    result = {"current": dict(latest)}
    if week_ago:
        result["week_ago"] = dict(week_ago)
        result["week_change"] = latest["total_messages"] - week_ago["total_messages"]
    if month_ago:
        result["month_ago"] = dict(month_ago)
        result["month_change"] = latest["total_messages"] - month_ago["total_messages"]
    return result


def get_new_senders_since(epoch):
    """Senders whose first appearance in sender_history is after the given epoch."""
    db = get_db()
    rows = db.execute("""
        SELECT from_email, from_name, MIN(recorded_at) as first_seen, MAX(message_count) as count
        FROM sender_history
        GROUP BY from_email
        HAVING first_seen > ?
        ORDER BY first_seen DESC
        LIMIT 50
    """, (epoch,)).fetchall()
    return [dict(r) for r in rows]


def get_composition_shift(weeks=4):
    """Category breakdown over time from snapshots."""
    db = get_db()
    now = int(time.time())
    cutoff = now - weeks * 7 * 86400
    rows = db.execute("""
        SELECT sh.category, ss.scanned_at, SUM(sh.message_count) as count
        FROM sender_history sh
        JOIN scan_snapshots ss ON sh.snapshot_id = ss.id
        WHERE ss.scanned_at > ?
        GROUP BY sh.category, ss.id
        ORDER BY ss.scanned_at
    """, (cutoff,)).fetchall()
    # Group by snapshot
    snapshots = {}
    for r in rows:
        ts = r["scanned_at"]
        if ts not in snapshots:
            snapshots[ts] = {}
        snapshots[ts][r["category"]] = r["count"]
    return [{"timestamp": ts, "categories": cats} for ts, cats in sorted(snapshots.items())]


# --- Triage actions (Feature 7: Ghost Rules) ---

def log_triage_action(sender_email, sender_name, action, source="list", message_count=0):
    """Log a user action for pattern detection."""
    db = get_db()
    db.execute(
        """INSERT INTO triage_actions
           (sender_email, sender_name, action, source, message_count, acted_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (sender_email, sender_name, action, source, message_count, int(time.time()))
    )
    db.commit()


def detect_ghost_rules(min_consecutive=5):
    """Analyze triage_actions for consistent patterns. Returns new pending rules."""
    db = get_db()
    # Get senders with repeated same action
    rows = db.execute("""
        SELECT sender_email, sender_name, action, COUNT(*) as cnt
        FROM triage_actions
        WHERE action != 'keep'
        GROUP BY sender_email, action
        HAVING cnt >= ?
        ORDER BY cnt DESC
    """, (min_consecutive,)).fetchall()

    new_rules = []
    for r in rows:
        email = r["sender_email"]
        action = r["action"]
        count = r["cnt"]
        # Check not already suggested for this sender+action
        existing = db.execute(
            "SELECT id FROM ghost_rules WHERE sender_email = ? AND suggested_action = ?",
            (email, action)
        ).fetchone()
        if existing:
            continue
        # Check that recent actions are consistent (last N are all the same)
        recent = db.execute(
            "SELECT action FROM triage_actions WHERE sender_email = ? ORDER BY acted_at DESC LIMIT ?",
            (email, min_consecutive)
        ).fetchall()
        if len(recent) >= min_consecutive and all(a["action"] == action for a in recent):
            action_map = {"archive": "auto-archive", "delete": "auto-delete", "block": "auto-block"}
            suggested = action_map.get(action, action)
            desc = f"You've {action}d {count} consecutive emails from {r['sender_name'] or email}"
            db.execute(
                """INSERT INTO ghost_rules
                   (sender_email, suggested_action, confidence, pattern_description, consecutive_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (email, suggested, min(1.0, count / 10), desc, count, int(time.time()))
            )
            new_rules.append({"sender_email": email, "suggested_action": suggested,
                              "description": desc, "count": count})
    db.commit()
    return new_rules


def get_pending_ghost_rules():
    """Return all pending (unaccepted, undismissed) ghost rules."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM ghost_rules WHERE status = 'pending' ORDER BY confidence DESC, consecutive_count DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def update_ghost_rule_status(rule_id, status):
    db = get_db()
    db.execute("UPDATE ghost_rules SET status = ? WHERE id = ?", (status, rule_id))
    db.commit()


def get_ghost_rule(rule_id):
    db = get_db()
    row = db.execute("SELECT * FROM ghost_rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else None


# --- Hygiene Score (Feature 1) ---

BADGE_DEFS = [
    ("pruned_100", "Pruned 100 emails", "🧹", lambda s: s.get("emails_cleaned", 0) >= 100),
    ("pruned_500", "Pruned 500 emails", "🔥", lambda s: s.get("emails_cleaned", 0) >= 500),
    ("pruned_1k", "Pruned 1,000 emails", "💪", lambda s: s.get("emails_cleaned", 0) >= 1000),
    ("pruned_5k", "Pruned 5,000 emails", "🏆", lambda s: s.get("emails_cleaned", 0) >= 5000),
    ("reclaimed_100mb", "Reclaimed 100 MB", "💾", lambda s: s.get("storage_freed_bytes", 0) >= 100 * 1024 * 1024),
    ("reclaimed_1gb", "Reclaimed 1 GB", "🗄️", lambda s: s.get("storage_freed_bytes", 0) >= 1024 * 1024 * 1024),
    ("first_scan", "First Scan", "👀", lambda s: True),  # always earned once you scan
]


def compute_hygiene_score():
    """Compute inbox hygiene score (0-100) from current messages cache."""
    db = get_db()
    now = int(time.time())

    row = db.execute("""
        SELECT COUNT(*) as total,
               SUM(CASE WHEN unread = 1 THEN 1 ELSE 0 END) as unread_count,
               SUM(CASE WHEN spam_score >= 50 THEN 1 ELSE 0 END) as marketing_count,
               SUM(CASE WHEN spam_score < 30 AND has_unsubscribe = 0 THEN 1 ELSE 0 END) as human_count,
               AVG(? - epoch) as avg_age_seconds,
               SUM(size) as total_size
        FROM messages
    """, (now,)).fetchone()

    total = row["total"] or 1
    unread = row["unread_count"] or 0
    marketing = row["marketing_count"] or 0
    human = row["human_count"] or 0
    avg_age_days = (row["avg_age_seconds"] or 0) / 86400
    total_size = row["total_size"] or 0

    # Component scores (each 0-20)
    unread_ratio = unread / total
    unread_score = round(20 * (1 - min(unread_ratio, 1)))

    marketing_ratio = marketing / total
    sub_human_score = round(20 * (1 - min(marketing_ratio, 1)))

    age_score = round(20 * max(0, 1 - avg_age_days / 365))

    avg_size = total_size / total if total else 0
    storage_score = round(20 * max(0, 1 - avg_size / 100000))  # penalize >100KB avg

    # Actions: based on stats
    stats = load_stats()
    actions_this_session = stats.get("emails_cleaned", 0)
    actions_score = round(20 * min(1, actions_this_session / 100))

    score = min(100, unread_score + sub_human_score + age_score + storage_score + actions_score)

    return {
        "score": score,
        "unread_ratio": round(unread_ratio, 3),
        "sub_to_human_ratio": round(marketing_ratio, 3),
        "avg_email_age_days": round(avg_age_days, 1),
        "storage_efficiency": round(storage_score / 20, 3),
        "actions_taken_score": round(actions_score / 20, 3),
        "components": {
            "unread": unread_score,
            "marketing": sub_human_score,
            "age": age_score,
            "storage": storage_score,
            "actions": actions_score,
        }
    }


def save_hygiene_score(score_data):
    """Save a hygiene score. Only saves if last save was >1 hour ago."""
    db = get_db()
    recent = db.execute(
        "SELECT id FROM hygiene_scores WHERE computed_at > ?",
        (int(time.time()) - 3600,)
    ).fetchone()
    if recent:
        return
    db.execute(
        """INSERT INTO hygiene_scores
           (score, unread_ratio, sub_to_human_ratio, avg_email_age_days, storage_efficiency, actions_taken_score, computed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (score_data["score"], score_data["unread_ratio"], score_data["sub_to_human_ratio"],
         score_data["avg_email_age_days"], score_data["storage_efficiency"],
         score_data["actions_taken_score"], int(time.time()))
    )
    db.commit()


def get_hygiene_history(limit=12):
    """Return recent hygiene scores for trend charting."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM hygiene_scores ORDER BY computed_at DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_hygiene_streak():
    """Count consecutive weeks where score improved or stayed same."""
    history = get_hygiene_history(52)
    if len(history) < 2:
        return 0
    streak = 0
    for i in range(len(history) - 1, 0, -1):
        if history[i]["score"] >= history[i - 1]["score"]:
            streak += 1
        else:
            break
    return streak


def check_and_award_badges():
    """Check thresholds and award any new badges. Returns newly earned."""
    db = get_db()
    stats = load_stats()
    newly_earned = []
    for key, label, icon, check_fn in BADGE_DEFS:
        existing = db.execute("SELECT id FROM hygiene_badges WHERE badge_key = ?", (key,)).fetchone()
        if not existing and check_fn(stats):
            db.execute(
                "INSERT INTO hygiene_badges (badge_key, badge_label, badge_icon, earned_at) VALUES (?, ?, ?, ?)",
                (key, label, icon, int(time.time()))
            )
            newly_earned.append({"key": key, "label": label, "icon": icon})
    db.commit()
    return newly_earned


def get_badges():
    db = get_db()
    rows = db.execute("SELECT * FROM hygiene_badges ORDER BY earned_at").fetchall()
    return [dict(r) for r in rows]


# --- Subscription Decay Radar (Feature 3) ---

def get_decaying_subscriptions(min_snapshots=2):
    """Find subscriptions with declining engagement over time."""
    db = get_db()
    # Get senders that have unsubscribe headers and appear in multiple snapshots
    rows = db.execute("""
        SELECT sh.from_email, sh.from_name, sh.snapshot_id,
               sh.read_rate, sh.message_count, sh.unread_count,
               sh.has_unsubscribe, sh.spam_score, ss.scanned_at
        FROM sender_history sh
        JOIN scan_snapshots ss ON sh.snapshot_id = ss.id
        WHERE sh.has_unsubscribe = 1 OR sh.spam_score >= 30
        ORDER BY sh.from_email, ss.scanned_at
    """).fetchall()

    if not rows:
        return []

    # Group by sender
    by_sender = defaultdict(list)
    for r in rows:
        by_sender[r["from_email"]].append(dict(r))

    decaying = []
    now = int(time.time())
    for email, history in by_sender.items():
        if len(history) < min_snapshots:
            continue

        latest = history[-1]
        count = latest["message_count"]
        if count < 3:
            continue

        # Compute engagement metrics
        read_rate = latest["read_rate"]
        unread_pct = (latest["unread_count"] / count * 100) if count else 0

        # Frequency: messages per week based on spread
        first_scan = history[0]["scanned_at"]
        weeks = max(1, (now - first_scan) / (7 * 86400))
        freq_per_week = count / weeks

        # Simple decay: low read rate + high frequency = decaying
        decay_score = 0
        if read_rate <= 10:
            decay_score += 40
        elif read_rate <= 30:
            decay_score += 25
        elif read_rate <= 50:
            decay_score += 10

        if freq_per_week >= 3:
            decay_score += 30
        elif freq_per_week >= 1:
            decay_score += 15

        if unread_pct >= 80:
            decay_score += 20
        elif unread_pct >= 50:
            decay_score += 10

        # Read rate decline over snapshots
        if len(history) >= 2:
            older_rates = [h["read_rate"] for h in history[:len(history)//2]]
            newer_rates = [h["read_rate"] for h in history[len(history)//2:]]
            avg_old = sum(older_rates) / len(older_rates) if older_rates else 0
            avg_new = sum(newer_rates) / len(newer_rates) if newer_rates else 0
            if avg_old > avg_new + 10:
                decay_score += 15

        if decay_score < 25:
            continue

        # Build suggestion text
        if read_rate == 0:
            suggestion = f"You never open emails from {latest['from_name'] or email} but they send ~{freq_per_week:.0f}/week"
        elif read_rate <= 20:
            suggestion = f"You rarely open emails from {latest['from_name'] or email} ({read_rate}% read rate, ~{freq_per_week:.1f}/week)"
        else:
            suggestion = f"Declining engagement with {latest['from_name'] or email} ({read_rate}% read, {count} msgs)"

        decaying.append({
            "email": email,
            "name": latest["from_name"] or email,
            "decay_score": min(100, decay_score),
            "read_rate": read_rate,
            "frequency_per_week": round(freq_per_week, 1),
            "message_count": count,
            "unread_pct": round(unread_pct),
            "suggestion": suggestion,
        })

    decaying.sort(key=lambda x: x["decay_score"], reverse=True)
    return decaying[:30]


# --- Storage Cost Visualizer (Feature 2) ---

def get_storage_by_sender(limit=50):
    """Top senders by total storage consumed."""
    db = get_db()
    rows = db.execute("""
        SELECT from_email, from_name, SUM(size) as total_size, COUNT(*) as count,
               AVG(size) as avg_size
        FROM messages
        GROUP BY from_email
        ORDER BY total_size DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def get_storage_summary():
    """Overall storage stats."""
    db = get_db()
    row = db.execute("""
        SELECT COUNT(*) as total_messages, SUM(size) as total_size,
               AVG(size) as avg_size, MAX(size) as max_size,
               COUNT(DISTINCT from_email) as total_senders
        FROM messages
    """).fetchone()
    return dict(row) if row else {}


def get_attachment_hoarders(min_avg_bytes=50000):
    """Senders with unusually large average message size (likely attachments)."""
    db = get_db()
    rows = db.execute("""
        SELECT from_email, from_name, COUNT(*) as count,
               SUM(size) as total_size, AVG(size) as avg_size
        FROM messages
        GROUP BY from_email
        HAVING avg_size > ? AND count >= 2
        ORDER BY total_size DESC
        LIMIT 20
    """, (min_avg_bytes,)).fetchall()
    return [dict(r) for r in rows]


# --- Quiet Hours Heatmap (Feature 4) ---

def get_email_heatmap():
    """Return 7x24 grid of email counts by day-of-week and hour.
    Uses SQL aggregation with strftime instead of loading all rows into Python."""
    db = get_db()
    # SQLite strftime %w: 0=Sunday..6=Saturday; we want Monday=0 so adjust
    rows = db.execute("""
        SELECT CAST(strftime('%w', epoch, 'unixepoch', 'localtime') AS INTEGER) AS dow,
               CAST(strftime('%H', epoch, 'unixepoch', 'localtime') AS INTEGER) AS hour,
               COUNT(*) AS cnt
        FROM messages WHERE epoch > 0
        GROUP BY dow, hour
    """).fetchall()

    grid = [[0] * 24 for _ in range(7)]  # grid[weekday][hour]
    for r in rows:
        # Convert Sunday=0 to Monday=0 convention
        weekday = (r["dow"] - 1) % 7
        grid[weekday][r["hour"]] = r["cnt"]
    return grid


def get_late_night_senders(start_hour=22, end_hour=7):
    """Senders who send most emails outside business hours.
    Uses SQL aggregation instead of loading all rows into Python."""
    db = get_db()
    rows = db.execute("""
        SELECT from_email, from_name,
               COUNT(*) AS total,
               SUM(CASE
                   WHEN CAST(strftime('%H', epoch, 'unixepoch', 'localtime') AS INTEGER) >= ?
                     OR CAST(strftime('%H', epoch, 'unixepoch', 'localtime') AS INTEGER) < ?
                   THEN 1 ELSE 0
               END) AS late_count
        FROM messages WHERE epoch > 0
        GROUP BY from_email
        HAVING late_count >= 3 AND total >= 3
        ORDER BY late_count DESC
        LIMIT 15
    """, (start_hour, end_hour)).fetchall()

    results = []
    for r in rows:
        pct = round(r["late_count"] / r["total"] * 100)
        if pct >= 25:
            results.append({
                "email": r["from_email"],
                "name": r["from_name"] or r["from_email"],
                "late_count": r["late_count"],
                "total": r["total"],
                "pct": pct,
            })
    return results


# --- Reply Debt Tracker (Feature 5) ---

def upsert_sent_messages(messages):
    if not messages:
        return
    db = get_db()
    now = int(time.time())
    db.executemany(
        "INSERT OR REPLACE INTO sent_messages_cache (id, to_email, subject, epoch, fetched_at) VALUES (?, ?, ?, ?, ?)",
        [(m["id"], m["to_email"], m.get("subject", ""), m.get("epoch", 0), now) for m in messages]
    )
    db.commit()


def get_sent_count():
    db = get_db()
    row = db.execute("SELECT COUNT(*) as cnt FROM sent_messages_cache").fetchone()
    return row["cnt"]


def get_reply_debt():
    """Find inbox messages from real humans that likely need a reply."""
    db = get_db()
    now = int(time.time())

    # Get "human" senders: low spam score, no unsubscribe header
    human_msgs = db.execute("""
        SELECT m.id, m.from_email, m.from_name, m.subject, m.epoch, m.snippet
        FROM messages m
        WHERE m.spam_score < 30
          AND m.has_unsubscribe = 0
          AND m.unread = 1
        ORDER BY m.epoch DESC
    """).fetchall()

    if not human_msgs:
        return []

    # Get all sent-to emails for quick lookup
    sent_rows = db.execute("SELECT to_email, MAX(epoch) as last_sent FROM sent_messages_cache GROUP BY to_email").fetchall()
    sent_map = {r["to_email"]: r["last_sent"] for r in sent_rows}

    # Find bidirectional senders (we've sent to them before = relationship)
    bidir = db.execute("""
        SELECT DISTINCT s.to_email
        FROM sent_messages_cache s
        WHERE s.to_email IN (SELECT DISTINCT from_email FROM messages WHERE spam_score < 30)
    """).fetchall()
    bidir_set = {r["to_email"] for r in bidir}

    debt = []
    seen_senders = set()
    for m in human_msgs:
        email = m["from_email"]
        if email in seen_senders:
            continue
        seen_senders.add(email)

        # Check if we replied after this message
        last_sent = sent_map.get(email, 0)
        if last_sent > m["epoch"]:
            continue  # We replied after their message

        age_days = max(0, (now - m["epoch"]) / 86400)
        is_bidir = email in bidir_set

        # Urgency: bidirectional relationships + recency
        urgency = 0
        if is_bidir:
            urgency += 40
        if age_days <= 1:
            urgency += 30
        elif age_days <= 3:
            urgency += 20
        elif age_days <= 7:
            urgency += 10

        debt.append({
            "email": email,
            "name": m["from_name"] or email,
            "subject": m["subject"],
            "snippet": m["snippet"],
            "message_id": m["id"],
            "age_days": round(age_days, 1),
            "is_bidirectional": is_bidir,
            "urgency": min(100, urgency),
        })

    debt.sort(key=lambda x: (-x["urgency"], x["age_days"]))
    return debt[:20]


# --- Email DNA / Sender Profiles (Feature 9) ---

from inboxdna.classifiers import DARK_PATTERNS, KNOWN_TRACKER_DOMAINS, SENSITIVE_PATTERNS


def compute_sender_profile(sender_email):
    """Build a full behavioral profile for a sender.
    Returns cached profile if computed within the last 5 minutes."""
    import re
    from datetime import datetime
    db = get_db()
    now = int(time.time())

    # Check cache first — return if fresh (< 5 minutes old)
    cached = db.execute(
        "SELECT profile_data, updated_at FROM sender_profiles WHERE sender_email = ?",
        (sender_email,)
    ).fetchone()
    if cached and cached["profile_data"] and (now - cached["updated_at"]) < 300:
        try:
            return json.loads(cached["profile_data"])
        except (json.JSONDecodeError, TypeError):
            pass

    msgs = db.execute(
        "SELECT * FROM messages WHERE from_email = ? ORDER BY epoch", (sender_email,)
    ).fetchall()
    if not msgs:
        return None

    count = len(msgs)
    name = msgs[-1]["from_name"] or sender_email
    total_size = sum(m["size"] for m in msgs)
    avg_size = total_size // count if count else 0
    unread = sum(1 for m in msgs if m["unread"])
    read_rate = round((count - unread) / count * 100) if count else 0

    # Frequency
    epochs = [m["epoch"] for m in msgs if m["epoch"] > 0]
    if len(epochs) >= 2:
        span_weeks = max(1, (epochs[-1] - epochs[0]) / (7 * 86400))
        freq_per_week = round(count / span_weeks, 1)
    else:
        freq_per_week = 0

    # Frequency trend from sender_history
    history = db.execute("""
        SELECT message_count, recorded_at FROM sender_history
        WHERE from_email = ? ORDER BY recorded_at
    """, (sender_email,)).fetchall()
    freq_trend = "stable"
    if len(history) >= 2:
        first_half = [h["message_count"] for h in history[:len(history)//2]]
        second_half = [h["message_count"] for h in history[len(history)//2:]]
        avg_first = sum(first_half) / len(first_half) if first_half else 0
        avg_second = sum(second_half) / len(second_half) if second_half else 0
        if avg_second > avg_first * 1.2:
            freq_trend = "increasing"
        elif avg_second < avg_first * 0.8:
            freq_trend = "decreasing"

    # Sending pattern: day-of-week distribution
    day_dist = [0] * 7
    hour_dist = [0] * 24
    for e in epochs:
        try:
            dt = datetime.fromtimestamp(e)
            day_dist[dt.weekday()] += 1
            hour_dist[dt.hour] += 1
        except (OSError, ValueError):
            pass

    # Dark pattern detection on subjects
    dark_found = []
    for m in msgs:
        subj = m["subject"] or ""
        for pattern_name, pattern in DARK_PATTERNS:
            if re.search(pattern, subj):
                if not any(d["type"] == pattern_name for d in dark_found):
                    dark_found.append({"type": pattern_name, "example": subj[:80]})
                break

    # Tracking pixel count from privacy audit
    tracker_count = 0
    row = db.execute(
        "SELECT COUNT(*) as cnt FROM privacy_audit_results WHERE sender_email = ? AND finding_type = 'tracking_pixel'",
        (sender_email,)
    ).fetchone()
    if row:
        tracker_count = row["cnt"]

    # Respect score (starts at 100, deductions)
    respect = 100
    if tracker_count > 0:
        respect -= min(20, tracker_count * 5)
    if len(dark_found) > 0:
        respect -= min(20, len(dark_found) * 10)
    if freq_per_week > 5:
        respect -= 15
    elif freq_per_week > 3:
        respect -= 5
    if read_rate < 20 and count >= 5:
        respect -= 15
    if freq_trend == "increasing":
        respect -= 10
    # Bonuses
    if read_rate > 80:
        respect += 10
    if any(m["has_unsubscribe"] for m in msgs):
        respect += 5
    respect = max(0, min(100, respect))

    # Triage action history
    actions = db.execute(
        "SELECT action, COUNT(*) as cnt FROM triage_actions WHERE sender_email = ? GROUP BY action",
        (sender_email,)
    ).fetchall()
    action_history = {a["action"]: a["cnt"] for a in actions}

    profile = {
        "email": sender_email,
        "name": name,
        "count": count,
        "unread": unread,
        "read_rate": read_rate,
        "avg_size": avg_size,
        "total_size": total_size,
        "freq_per_week": freq_per_week,
        "freq_trend": freq_trend,
        "day_distribution": day_dist,
        "hour_distribution": hour_dist,
        "dark_patterns": dark_found,
        "tracking_pixel_count": tracker_count,
        "respect_score": respect,
        "action_history": action_history,
        "spam_score": msgs[-1]["spam_score"],
        "has_unsubscribe": bool(msgs[-1]["has_unsubscribe"]),
        "category": msgs[-1]["category"],
    }

    # Cache it
    db.execute(
        """INSERT OR REPLACE INTO sender_profiles
           (sender_email, display_name, avg_frequency_per_week, avg_message_size,
            tracking_pixel_count, frequency_trend, respect_score, dark_patterns, profile_data, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (sender_email, name, freq_per_week, avg_size, tracker_count, freq_trend,
         respect, json.dumps(dark_found), json.dumps(profile), now)
    )
    db.commit()
    return profile


# --- Privacy Audit (Feature 8) ---



def save_privacy_finding(message_id, sender_email, finding_type, detail, severity="medium"):
    db = get_db()
    db.execute(
        """INSERT INTO privacy_audit_results (message_id, sender_email, finding_type, finding_detail, severity, audited_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (message_id, sender_email, finding_type, detail, severity, int(time.time()))
    )
    db.commit()


def save_privacy_findings_batch(findings):
    """Save multiple privacy findings in a single commit.
    findings: list of (message_id, sender_email, finding_type, detail, severity) tuples."""
    if not findings:
        return
    db = get_db()
    now = int(time.time())
    db.executemany(
        """INSERT INTO privacy_audit_results (message_id, sender_email, finding_type, finding_detail, severity, audited_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        [(f[0], f[1], f[2], f[3], f[4], now) for f in findings]
    )
    db.commit()


def get_privacy_report():
    """Aggregated privacy audit results."""
    db = get_db()
    total_scanned = db.execute("SELECT COUNT(DISTINCT message_id) as cnt FROM privacy_audit_results").fetchone()["cnt"]

    tracker_senders = db.execute("""
        SELECT sender_email, COUNT(*) as cnt
        FROM privacy_audit_results
        WHERE finding_type = 'tracking_pixel'
        GROUP BY sender_email
        ORDER BY cnt DESC
    """).fetchall()

    sensitive_findings = db.execute("""
        SELECT * FROM privacy_audit_results
        WHERE finding_type = 'sensitive_data'
        ORDER BY severity DESC, audited_at DESC
        LIMIT 20
    """).fetchall()

    totals = db.execute("""
        SELECT finding_type, COUNT(*) as cnt
        FROM privacy_audit_results
        GROUP BY finding_type
    """).fetchall()

    return {
        "total_scanned": total_scanned,
        "tracker_senders": [dict(r) for r in tracker_senders],
        "sensitive_findings": [dict(r) for r in sensitive_findings],
        "totals": {r["finding_type"]: r["cnt"] for r in totals},
    }


def get_recent_message_ids(limit=100):
    """Get recent message IDs for privacy scanning."""
    db = get_db()
    # Exclude already-scanned messages
    rows = db.execute("""
        SELECT m.id, m.from_email
        FROM messages m
        WHERE m.id NOT IN (SELECT DISTINCT message_id FROM privacy_audit_results)
        ORDER BY m.epoch DESC
        LIMIT ?
    """, (limit,)).fetchall()
    return [dict(r) for r in rows]


def clear_privacy_results():
    db = get_db()
    db.execute("DELETE FROM privacy_audit_results")
    db.commit()
