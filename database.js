const Database = require("better-sqlite3");
const bcrypt   = require("bcryptjs");
const path     = require("path");
const fs       = require("fs");

// ── Persistent path for Railway, local fallback ───────────────────────────────
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, "sleep_diary.db");

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

// ── Create tables ─────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    password   TEXT NOT NULL,
    sec_q      INTEGER NOT NULL DEFAULT 0,
    sec_a      TEXT NOT NULL DEFAULT '',
    is_admin   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    date        TEXT NOT NULL,
    bed_time    TEXT NOT NULL,
    wake_time   TEXT NOT NULL,
    duration    REAL NOT NULL,
    screen_time REAL NOT NULL,
    energy      INTEGER NOT NULL,
    notes       TEXT DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, date)
  );
`);

// ── Seed admin account ────────────────────────────────────────────────────────
const adminExists = db.prepare("SELECT id FROM users WHERE username = 'admin'").get();
if (!adminExists) {
  const hash = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)").run("admin", hash);
  console.log("✅ Admin account created: admin / admin123");
}

// ── Prepared statements ───────────────────────────────────────────────────────
const stmts = {
  findUser:       db.prepare("SELECT * FROM users WHERE username = ?"),
  findUserById:   db.prepare("SELECT * FROM users WHERE id = ?"),
  createUser:     db.prepare("INSERT INTO users (username, password, sec_q, sec_a) VALUES (?, ?, ?, ?)"),
  updatePassword: db.prepare("UPDATE users SET password = ? WHERE username = ?"),
  listUsers:      db.prepare("SELECT id, username, created_at FROM users WHERE is_admin = 0"),
  upsertEntry: db.prepare(`
    INSERT INTO entries (user_id, date, bed_time, wake_time, duration, screen_time, energy, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, date) DO UPDATE SET
      bed_time    = excluded.bed_time,
      wake_time   = excluded.wake_time,
      duration    = excluded.duration,
      screen_time = excluded.screen_time,
      energy      = excluded.energy,
      notes       = excluded.notes
  `),
  getUserEntries: db.prepare("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC"),
  deleteEntry:    db.prepare("DELETE FROM entries WHERE id = ? AND user_id = ?"),
  entriesByUser:  db.prepare("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC"),
};

module.exports = { db, stmts };
