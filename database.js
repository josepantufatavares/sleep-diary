const initSqlJs = require("sql.js");
const bcrypt    = require("bcryptjs");
const path      = require("path");
const fs        = require("fs");

// ── Persistent path ───────────────────────────────────────────────────────────
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, "sleep_diary.db");

console.log("📂 DB path:", DB_PATH);

const ready = initSqlJs().then(SQL => {
  // Load existing DB from disk or create new
  let db;
  if (fs.existsSync(DB_PATH)) {
    console.log("📖 Loading existing database from disk...");
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
    console.log("✅ Database loaded from disk.");
  } else {
    console.log("🆕 Creating new database...");
    db = new SQL.Database();
  }

  // ── Save to disk ────────────────────────────────────────────────────────────
  const save = () => {
    try {
      const data = db.export();
      const buf  = Buffer.from(data);
      fs.writeFileSync(DB_PATH, buf);
    } catch (e) {
      console.error("❌ Failed to save database:", e.message);
    }
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
  const adminRow = db.exec("SELECT id FROM users WHERE username = 'admin'");
  if (!adminRow.length || !adminRow[0].values.length) {
    const hash = bcrypt.hashSync("admin123", 10);
    db.run("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ["admin", hash]);
    save();
    console.log("✅ Admin account created.");
  }

  // ── Query helpers ───────────────────────────────────────────────────────────
  const all = (sql, params = []) => {
    try {
      const res = db.exec(sql, params);
      if (!res.length) return [];
      const { columns, values } = res[0];
      return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
    } catch (e) {
      console.error("❌ DB all() error:", e.message, sql);
      throw e;
    }
  };

  const get = (sql, params = []) => all(sql, params)[0] || null;

  const run = (sql, params = []) => {
    try {
      db.run(sql, params);
      save(); // persist every write immediately
    } catch (e) {
      console.error("❌ DB run() error:", e.message, sql);
      throw e;
    }
  };

  const lastId = () => {
    const r = db.exec("SELECT last_insert_rowid() as id");
    return r[0].values[0][0];
  };

  // ── Periodic save every 30s as safety net ──────────────────────────────────
  setInterval(save, 30000);

  // ── Save on process exit ────────────────────────────────────────────────────
  process.on("SIGTERM", () => { save(); console.log("💾 DB saved on SIGTERM."); });
  process.on("SIGINT",  () => { save(); console.log("💾 DB saved on SIGINT.");  });

  console.log("✅ Database ready.");
  return { run, all, get, lastId };
});

module.exports = { ready };
