const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const initSqlJs = require('sql.js');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '5mb' }));

const JWT_SECRET = 'tericasino-secret-key-2026';
const DB_FILE = './tericasino.db';
const hierarchy = ['user', 'mod', 'admin', 'coowner', 'owner'];

let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_FILE)) {
    db = new SQL.Database(fs.readFileSync(DB_FILE));
  } else {
    db = new SQL.Database();
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      teris TEXT DEFAULT '1000',
      role TEXT DEFAULT 'user',
      banned INTEGER DEFAULT 0,
      ban_reason TEXT,
      ban_until INTEGER,
      ban_by TEXT,
      created_at INTEGER DEFAULT 0,
      data TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS chat (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      message TEXT NOT NULL,
      system INTEGER DEFAULT 0,
      ts INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS modlog (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT, target TEXT, action TEXT, reason TEXT,
      ts INTEGER DEFAULT 0
    );
  `);
  saveDB();
  console.log('Datenbank bereit');
}

function saveDB() {
  fs.writeFileSync(DB_FILE, Buffer.from(db.export()));
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  return row;
}

function dbAll(sql, params = []) {
  const results = [], stmt = db.prepare(sql);
  stmt.bind(params);
  while (stmt.step()) results.push(stmt.getAsObject());
  stmt.free();
  return results;
}

function dbRun(sql, params = []) {
  db.run(sql, params);
  saveDB();
}

function sanitizeUser(u) {
  if (!u) return null;
  const { password, ...safe } = u;
  // Parse data field
  try { safe.data = typeof safe.data === 'string' ? JSON.parse(safe.data) : (safe.data || {}); } catch { safe.data = {}; }
  return safe;
}

function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Nicht eingeloggt' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    req.dbUser = dbGet('SELECT * FROM users WHERE name=?', [req.user.name]);
    if (!req.dbUser) return res.status(401).json({ error: 'User nicht gefunden' });
    next();
  } catch { res.status(401).json({ error: 'Ungültiger Token' }); }
}

function requireRole(...roles) {
  return (req, res, next) => {
    const userLevel = hierarchy.indexOf(req.dbUser.role);
    const required = Math.min(...roles.map(r => hierarchy.indexOf(r)));
    if (userLevel >= required) return next();
    res.status(403).json({ error: 'Keine Berechtigung' });
  };
}

// ─── HTML AUSLIEFERN ───
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'TeriCasino.html')));

// ─── REGISTER ───
app.post('/register', async (req, res) => {
  const { name, password } = req.body;
  if (!name || !password) return res.status(400).json({ error: 'Name und Passwort erforderlich' });
  if (name.length < 3) return res.status(400).json({ error: 'Name mindestens 3 Zeichen' });
  if (dbGet('SELECT id FROM users WHERE name=?', [name])) return res.status(400).json({ error: 'Name bereits vergeben' });

  const hashed = await bcrypt.hash(password, 10);
  const count = dbGet('SELECT COUNT(*) as c FROM users', []);
  const role = count.c == 0 ? 'owner' : 'user';
  const ts = Date.now();
  const initData = JSON.stringify({ ranks: [], cosmetics: [], boosts: [], inventory: { boosts: {} }, stats: { games: 0, logins: 0 }, perks: {}, avatar: '💠', vip: null, playMs: 0, acceptedAGB: false, winFeed: [] });

  dbRun('INSERT INTO users (name, password, role, teris, created_at, data) VALUES (?, ?, ?, ?, ?, ?)', [name, hashed, role, '1000', ts, initData]);

  const user = dbGet('SELECT * FROM users WHERE name=?', [name]);
  const token = jwt.sign({ name }, JWT_SECRET, { expiresIn: '30d' });
  res.status(201).json({ token, user: sanitizeUser(user) });
});

// ─── LOGIN ───
app.post('/login', async (req, res) => {
  const { name, password } = req.body;
  const user = dbGet('SELECT * FROM users WHERE name=?', [name]);
  if (!user) return res.status(401).json({ error: 'Falscher Name oder Passwort' });
  if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Falscher Name oder Passwort' });

  if (user.banned) {
    if (user.ban_until && Date.now() > user.ban_until) {
      dbRun('UPDATE users SET banned=0, ban_reason=NULL, ban_until=NULL WHERE name=?', [name]);
    } else {
      return res.status(403).json({ error: 'Gebannt', reason: user.ban_reason, until: user.ban_until });
    }
  }

  const token = jwt.sign({ name }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: sanitizeUser(dbGet('SELECT * FROM users WHERE name=?', [name])) });
});

// ─── MICH LADEN ───
app.get('/me', auth, (req, res) => res.json(sanitizeUser(req.dbUser)));

// ─── ALLE USER ───
app.get('/users', auth, (req, res) => {
  const users = dbAll('SELECT * FROM users ORDER BY CAST(teris AS INTEGER) DESC', []);
  res.json(users.map(sanitizeUser));
});

// ─── USER DATEN SPEICHERN (alles: teris, stats, inventory, etc.) ───
app.post('/save', auth, (req, res) => {
  const { teris, data } = req.body;
  const dataStr = JSON.stringify(data || {});
  dbRun('UPDATE users SET teris=?, data=? WHERE name=?', [String(teris || '0'), dataStr, req.dbUser.name]);
  res.json({ ok: true });
});

// ─── TERIS (Admin) ───
app.post('/admin/teris', auth, requireRole('mod'), (req, res) => {
  const { target, amount } = req.body;
  const t = dbGet('SELECT * FROM users WHERE name=?', [target]);
  if (!t) return res.status(404).json({ error: 'User nicht gefunden' });
  const newBalance = Math.max(0, Number(t.teris || 0) + amount);
  dbRun('UPDATE users SET teris=? WHERE name=?', [String(newBalance), target]);
  dbRun('INSERT INTO modlog (actor,target,action,reason,ts) VALUES (?,?,?,?,?)',
    [req.dbUser.name, target, amount > 0 ? 'give' : 'take', `${Math.abs(amount)} Teris`, Date.now()]);
  io.emit('userUpdate', { name: target, teris: String(newBalance) });
  res.json({ success: true, teris: String(newBalance) });
});

// ─── BAN ───
app.post('/ban', auth, requireRole('mod'), (req, res) => {
  const { target, reason, until } = req.body;
  const t = dbGet('SELECT * FROM users WHERE name=?', [target]);
  if (!t) return res.status(404).json({ error: 'User nicht gefunden' });
  if (t.role === 'owner') return res.status(403).json({ error: 'Owner kann nicht gebannt werden' });
  if (hierarchy.indexOf(t.role) >= hierarchy.indexOf(req.dbUser.role)) return res.status(403).json({ error: 'Keine Berechtigung' });

  dbRun('UPDATE users SET banned=1, ban_reason=?, ban_until=?, ban_by=? WHERE name=?', [reason || '', until || null, req.dbUser.name, target]);
  dbRun('INSERT INTO modlog (actor,target,action,reason,ts) VALUES (?,?,?,?,?)', [req.dbUser.name, target, 'ban', reason || '', Date.now()]);
  const msg = `⛔ ${target} wurde gebannt${reason ? ` (${reason})` : ''}.`;
  dbRun('INSERT INTO chat (username,message,system,ts) VALUES (?,?,1,?)', [null, msg, Date.now()]);
  io.emit('chatMessage', { system: true, text: msg, ts: Date.now() });
  io.emit('banned', { name: target });
  res.json({ success: true });
});

app.post('/unban', auth, requireRole('mod'), (req, res) => {
  const { target } = req.body;
  dbRun('UPDATE users SET banned=0, ban_reason=NULL, ban_until=NULL WHERE name=?', [target]);
  dbRun('INSERT INTO modlog (actor,target,action,reason,ts) VALUES (?,?,?,?,?)', [req.dbUser.name, target, 'unban', '', Date.now()]);
  const msg = `✅ ${target} wurde entbannt.`;
  dbRun('INSERT INTO chat (username,message,system,ts) VALUES (?,?,1,?)', [null, msg, Date.now()]);
  io.emit('chatMessage', { system: true, text: msg, ts: Date.now() });
  res.json({ success: true });
});

// ─── ROLLEN ───
app.post('/admin/role', auth, requireRole('admin'), (req, res) => {
  const { target, role } = req.body;
  if (!['user','mod','admin','coowner'].includes(role)) return res.status(400).json({ error: 'Ungültige Rolle' });
  const t = dbGet('SELECT * FROM users WHERE name=?', [target]);
  if (!t) return res.status(404).json({ error: 'User nicht gefunden' });
  if (t.role === 'owner') return res.status(403).json({ error: 'Owner unveränderbar' });
  if (hierarchy.indexOf(role) >= hierarchy.indexOf(req.dbUser.role)) return res.status(403).json({ error: 'Keine Berechtigung' });
  dbRun('UPDATE users SET role=? WHERE name=?', [role, target]);
  dbRun('INSERT INTO modlog (actor,target,action,reason,ts) VALUES (?,?,?,?,?)', [req.dbUser.name, target, 'role', role, Date.now()]);
  io.emit('userUpdate', { name: target, role });
  res.json({ success: true });
});

// ─── CHAT ───
app.get('/chat', auth, (req, res) => res.json(dbAll('SELECT * FROM chat ORDER BY ts DESC LIMIT 100', []).reverse()));
app.post('/chat/clear', auth, requireRole('mod'), (req, res) => {
  dbRun('DELETE FROM chat');
  dbRun('INSERT INTO chat (username,message,system,ts) VALUES (?,?,1,?)', [null, 'Chat wurde geleert.', Date.now()]);
  io.emit('chatClear');
  res.json({ success: true });
});

app.get('/modlog', auth, requireRole('mod'), (req, res) => res.json(dbAll('SELECT * FROM modlog ORDER BY ts DESC LIMIT 200', [])));

// ─── SOCKET.IO ───
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, JWT_SECRET);
    socket.dbUser = dbGet('SELECT * FROM users WHERE name=?', [socket.user.name]);
    next();
  } catch { next(new Error('Ungültiger Token')); }
});

io.on('connection', (socket) => {
  const { name } = socket.dbUser;
  console.log('Verbunden: ' + name);
  socket.on('chatMessage', (text) => {
    if (!text || text.length > 500) return;
    const u = dbGet('SELECT * FROM users WHERE name=?', [name]);
    if (u.banned) return;
    const ts = Date.now();
    dbRun('INSERT INTO chat (username,message,system,ts) VALUES (?,?,0,?)', [name, text, ts]);
    io.emit('chatMessage', { username: name, message: text, system: 0, ts });
  });
  socket.on('disconnect', () => console.log('Getrennt: ' + name));
});

// ─── START ───
initDB().then(() => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log('TeriCasino laeuft auf Port ' + PORT));
});
