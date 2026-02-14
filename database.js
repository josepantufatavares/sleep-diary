const Database = require("better-sqlite3");
const path = require("path");

const DB_PATH = process.env.RAILWAY_VOLUME_MOUNT_PATH
  ? path.join(process.env.RAILWAY_VOLUME_MOUNT_PATH, "sleep_diary.db")
  : path.join(__dirname, "sleep_diary.db");

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma("journal_mode = WAL");

// ── Create tables ─────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT UNIQUE NOT NULL,
    password  TEXT NOT NULL,
    sec_q     INTEGER NOT NULL DEFAULT 0,
    sec_a     TEXT NOT NULL DEFAULT '',
    is_admin  INTEGER NOT NULL DEFAULT 0,
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

// ── Seed admin account if not exists ─────────────────────────────────────────
const bcrypt = require("bcryptjs");
const adminExists = db.prepare("SELECT id FROM users WHERE username = 'admin'").get();
if (!adminExists) {
  const hash = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)").run("admin", hash);
  console.log("✅ Admin account created: admin / admin123");
}

// ── Prepared statements ───────────────────────────────────────────────────────
const stmts = {
  // Users
  findUser:       db.prepare("SELECT * FROM users WHERE username = ?"),
  findUserById:   db.prepare("SELECT * FROM users WHERE id = ?"),
  createUser:     db.prepare("INSERT INTO users (username, password, sec_q, sec_a) VALUES (?, ?, ?, ?)"),
  updatePassword: db.prepare("UPDATE users SET password = ? WHERE username = ?"),
  listUsers:      db.prepare("SELECT id, username, created_at FROM users WHERE is_admin = 0"),

  // Entries
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
  getUserEntries:  db.prepare("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC"),
  deleteEntry:     db.prepare("DELETE FROM entries WHERE id = ? AND user_id = ?"),
  allEntries:      db.prepare("SELECT e.*, u.username FROM entries e JOIN users u ON e.user_id = u.id ORDER BY e.date DESC"),
  entriesByUser:   db.prepare("SELECT * FROM entries WHERE user_id = ? ORDER BY date DESC"),
};

module.exports = { db, stmts };
