const initSqlJs = require("sql.js");
const path      = require("path");
const fs        = require("fs");

// ── Persistent path ───────────────────────────────────────────────────────────
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, "sleep_diary.db");

// ── sql.js uses an async init — we export a promise ──────────────────────────
let db;

const ready = initSqlJs().then(SQL => {
  // Load existing DB from disk, or create new
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  // Persist to disk on every write
  const save = () => {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  };

  // ── Create tables ───────────────────────────────────────────────────────────
  db.run(`
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
      user_id     INTEGER NOT NULL,
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
  save();

  // ── Seed admin ──────────────────────────────────────────────────────────────
  const bcrypt = require("bcryptjs");
  const adminRow = db.exec("SELECT id FROM users WHERE username = 'admin'");
  if (!adminRow.length || !adminRow[0].values.length) {
    const hash = bcrypt.hashSync("admin123", 10);
    db.run("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ["admin", hash]);
    save();
    console.log("✅ Admin account created: admin / admin123");
  }

  // ── Helper: run a write query and persist ───────────────────────────────────
  const run = (sql, params = []) => {
    db.run(sql, params);
    save();
    return db;
  };

  // ── Helper: return array of row objects ─────────────────────────────────────
  const all = (sql, params = []) => {
    const res = db.exec(sql, params);
    if (!res.length) return [];
    const { columns, values } = res[0];
    return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
  };

  // ── Helper: return single row object ────────────────────────────────────────
  const get = (sql, params = []) => all(sql, params)[0] || null;

  // ── Helper: get last inserted id ────────────────────────────────────────────
  const lastId = () => {
    const r = db.exec("SELECT last_insert_rowid() as id");
    return r[0].values[0][0];
  };

  return { run, all, get, lastId };
});

module.exports = { ready };
