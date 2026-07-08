const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const fs = require('fs');
const initSqlJs = require('sql.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// ===== KONFIGURASI =====
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const JWT_SECRET = 'rahasia-super-amun-2024';
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'presensi.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===== STATE ONLINE =====
const onlineUsers = new Map();

// ===== DATABASE HELPERS (didefinisikan dulu, diisi setelah init) =====
let db = null;
let dbRun, dbGet, dbAll;

function saveDB() {
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

// ===== INISIALISASI DATABASE (ASYNC) =====
async function initDatabase() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const buffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buffer);
  } else {
    db = new SQL.Database();
  }

  // Buat tabel
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
  saveDB();

  // Isi helper functions
  dbRun = (sql, params = []) => {
    db.run(sql, params);
    saveDB();
  };

  dbGet = (sql, params = []) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return undefined;
  };

  dbAll = (sql, params = []) => {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject());
    }
    stmt.free();
    return rows;
  };

  console.log('✅ Database siap (sql.js - pure JS)');
}

// ===== MIDDLEWARE JWT =====
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// ===== API AUTH =====
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Semua field harus diisi' });
  }
  try {
    const existing = dbGet('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing) {
      return res.status(400).json({ error: 'Username atau email sudah terdaftar' });
    }
    const password_hash = bcrypt.hashSync(password, 10);
    dbRun('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)', [username, email, password_hash]);

    const user = dbGet('SELECT id, username, email FROM users WHERE username = ?', [username]);
    dbRun('INSERT INTO activities (user_id, username, action) VALUES (?, ?, ?)', [user.id, username, 'register']);

    const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password harus diisi' });
  }
  try {
    const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: 'Username atau password salah' });
    }
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/me', authenticateToken, (req, res) => {
  const user = dbGet('SELECT id, username, email, created_at FROM users WHERE id = ?', [req.user.id]);
  res.json(user);
});

// ===== API USERS & ACTIVITIES =====
app.get('/api/users', authenticateToken, (req, res) => {
  const users = dbAll('SELECT id, username, email, created_at FROM users ORDER BY username');
  const onlineIds = new Set();
  for (const [_, u] of onlineUsers) {
    onlineIds.add(u.userId);
  }
  const result = users.map(u => ({ ...u, is_online: onlineIds.has(u.id) }));
  res.json(result);
});

app.get('/api/activities', authenticateToken, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const activities = dbAll('SELECT * FROM activities ORDER BY created_at DESC LIMIT ?', [limit]);
  res.json(activities);
});

// ===== SOCKET.IO =====
io.on('connection', (socket) => {
  console.log('🔌 New connection:', socket.id);

  socket.on('user-online', (data) => {
    const { userId, username } = data;
    onlineUsers.set(socket.id, { userId, username });
    dbRun('INSERT INTO activities (user_id, username, action) VALUES (?, ?, ?)', [userId, username, 'login']);
    broadcastOnlineUsers();
    socket.broadcast.emit('notification', {
      type: 'join',
      message: `${username} masuk ke sistem`,
      timestamp: new Date().toISOString()
    });
    io.emit('new-activity', {
      username,
      action: 'login',
      created_at: new Date().toISOString()
    });
    console.log(`✅ ${username} online`);
  });

  socket.on('disconnect', () => {
    const userData = onlineUsers.get(socket.id);
    if (userData) {
      const { userId, username } = userData;
      dbRun('INSERT INTO activities (user_id, username, action) VALUES (?, ?, ?)', [userId, username, 'logout']);
      onlineUsers.delete(socket.id);
      broadcastOnlineUsers();
      io.emit('notification', {
        type: 'leave',
        message: `${username} keluar dari sistem`,
        timestamp: new Date().toISOString()
      });
      io.emit('new-activity', {
        username,
        action: 'logout',
        created_at: new Date().toISOString()
      });
      console.log(`❌ ${username} offline`);
    }
  });

  socket.on('user-offline', (data) => {
    const { userId, username } = data;
    for (const [sid, u] of onlineUsers) {
      if (u.userId === userId) {
        onlineUsers.delete(sid);
        break;
      }
    }
    dbRun('INSERT INTO activities (user_id, username, action) VALUES (?, ?, ?)', [userId, username, 'logout']);
    broadcastOnlineUsers();
    io.emit('notification', {
      type: 'leave',
      message: `${username} keluar dari sistem`,
      timestamp: new Date().toISOString()
    });
    io.emit('new-activity', {
      username,
      action: 'logout',
      created_at: new Date().toISOString()
    });
  });
});

function broadcastOnlineUsers() {
  const onlineList = [];
  for (const [socketId, user] of onlineUsers) {
    onlineList.push({ socketId, userId: user.userId, username: user.username });
  }
  io.emit('online-users', onlineList);
}

// ===== START =====
initDatabase().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 Server jalan di http://localhost:${PORT}`);
  });
});
