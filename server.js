// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto');
const { makeWASocket, useMultiFileAuthState, fetchLatestBaileysVersion, Browsers, DisconnectReason, makeCacheableSignalKeyStore } = require('@whiskeysockets/baileys');
const pino = require('pino');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vector_crasher_secret_key_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ZentrixTechOfficial';

// Serve static files from public/ folder
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());
app.use(cors());

// ==================== FILE STORAGE ====================
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const BUGS_FILE = path.join(DATA_DIR, 'bugs.json');
const RESET_TOKENS_FILE = path.join(DATA_DIR, 'reset_tokens.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SESSIONS_DIR = path.join(__dirname, 'zentrixsessions');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(SESSIONS_DIR)) fs.mkdirSync(SESSIONS_DIR, { recursive: true });

// Initialize JSON files if not exist
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(BUGS_FILE)) fs.writeFileSync(BUGS_FILE, JSON.stringify([]));
if (!fs.existsSync(RESET_TOKENS_FILE)) fs.writeFileSync(RESET_TOKENS_FILE, JSON.stringify([]));

// Helper functions
const readJSON = (file) => JSON.parse(fs.readFileSync(file));
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

// ==================== AUTH MIDDLEWARE ====================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
}

function adminAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Admin token required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    req.admin = decoded;
    next();
  } catch (err) {
    res.status(403).json({ success: false, message: 'Invalid admin token' });
  }
}

// ==================== WHATSAPP SESSIONS STORAGE ====================
const activeSockets = new Map(); // userId -> { sock, phoneNumber }

async function startWhatsAppForUser(userId, phoneNumber) {
  const sessionPath = path.join(SESSIONS_DIR, `session_${phoneNumber}`);
  if (!fs.existsSync(sessionPath)) fs.mkdirSync(sessionPath, { recursive: true });
  try {
    const { version } = await fetchLatestBaileysVersion();
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const logger = pino({ level: 'silent' });
    const sock = makeWASocket({
      version,
      logger,
      browser: Browsers.macOS('Chrome'),
      printQRInTerminal: false,
      auth: {
        creds: state.creds,
        keys: makeCacheableSignalKeyStore(state.keys, logger)
      },
      markOnlineOnConnect: false
    });
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect } = update;
      if (connection === 'open') {
        console.log(`✅ WhatsApp connected for user ${userId} (${phoneNumber})`);
        activeSockets.set(userId, { sock, phoneNumber });
        // Update user record with phone and connected flag
        const users = readJSON(USERS_FILE);
        const userIndex = users.findIndex(u => u.id === userId);
        if (userIndex !== -1) {
          users[userIndex].phone = phoneNumber;
          users[userIndex].whatsappConnected = true;
          writeJSON(USERS_FILE, users);
        }
      }
      if (connection === 'close') {
        const error = lastDisconnect?.error;
        const statusCode = error?.output?.statusCode || error?.error?.statusCode;
        if (statusCode >= 500) {
          setTimeout(() => startWhatsAppForUser(userId, phoneNumber), 5000);
        } else {
          activeSockets.delete(userId);
          const users = readJSON(USERS_FILE);
          const userIndex = users.findIndex(u => u.id === userId);
          if (userIndex !== -1) users[userIndex].whatsappConnected = false;
          writeJSON(USERS_FILE, users);
        }
      }
    });
    return sock;
  } catch (err) {
    console.error(`WhatsApp start error for ${phoneNumber}:`, err);
    return null;
  }
}

// ==================== USER API ====================
app.post('/api/register', async (req, res) => {
  const { email, phone, age, password } = req.body;
  if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
  if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail addresses allowed' });
  if (password.length < 6) return res.json({ success: false, message: 'Password min 6 chars' });
  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email already exists' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = {
    id: crypto.randomUUID(),
    email,
    phone,
    age: parseInt(age),
    passwordHash: hashedPassword,
    approved: false,
    premium: false,
    whatsappConnected: false,
    avatar: null,
    gender: 'Other',
    country: '',
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeJSON(USERS_FILE, users);
  res.json({ success: true, message: 'Registration pending admin approval' });
});

app.post('/api/login', async (req, res) => {
  const { email, password, remember } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (!user) return res.json({ success: false, message: 'Invalid credentials' });
  if (!user.approved) return res.json({ success: false, message: 'Account pending approval', pendingApproval: true });
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) return res.json({ success: false, message: 'Invalid credentials' });
  const expiresIn = remember ? '7d' : '1d';
  const token = jwt.sign({ id: user.id, email: user.email, role: 'user' }, JWT_SECRET, { expiresIn });
  res.json({ success: true, token });
});

app.get('/api/user/profile', authenticateToken, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.json({ success: false, message: 'User not found' });
  res.json({
    success: true,
    user: {
      email: user.email,
      phone: user.phone,
      age: user.age,
      gender: user.gender,
      country: user.country,
      avatar: user.avatar,
      approved: user.approved,
      premium: user.premium,
      whatsappConnected: user.whatsappConnected
    }
  });
});

app.post('/api/user/update-profile', authenticateToken, (req, res) => {
  const { age, gender, country, phone } = req.body;
  const users = readJSON(USERS_FILE);
  const index = users.findIndex(u => u.id === req.user.id);
  if (index === -1) return res.json({ success: false, message: 'User not found' });
  if (age && (age < 13 || age > 100)) return res.json({ success: false, message: 'Invalid age' });
  if (phone && !/^\+?\d{10,15}$/.test(phone.replace(/\s/g, ''))) return res.json({ success: false, message: 'Invalid phone' });
  if (age) users[index].age = parseInt(age);
  if (gender) users[index].gender = gender;
  if (country) users[index].country = country;
  if (phone) users[index].phone = phone;
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

app.post('/api/user/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.json({ success: false, message: 'User not found' });
  const valid = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!valid) return res.json({ success: false, message: 'Current password incorrect' });
  if (newPassword.length < 6) return res.json({ success: false, message: 'New password too short' });
  user.passwordHash = await bcrypt.hash(newPassword, 10);
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

// Avatar upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, `avatar_${req.user.id}.jpg`)
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });
app.post('/api/user/upload-avatar', authenticateToken, upload.single('avatar'), (req, res) => {
  if (!req.file) return res.json({ success: false, message: 'No file' });
  const avatarUrl = `/uploads/avatar_${req.user.id}.jpg`;
  const users = readJSON(USERS_FILE);
  const index = users.findIndex(u => u.id === req.user.id);
  if (index !== -1) users[index].avatar = avatarUrl;
  writeJSON(USERS_FILE, users);
  res.json({ success: true, avatarUrl });
});

app.post('/api/user/delete-account', authenticateToken, (req, res) => {
  let users = readJSON(USERS_FILE);
  const newUsers = users.filter(u => u.id !== req.user.id);
  writeJSON(USERS_FILE, newUsers);
  activeSockets.delete(req.user.id);
  res.json({ success: true });
});

app.get('/api/user/status', authenticateToken, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  res.json({ success: true, premium: user?.premium || false, approved: user?.approved || false });
});

app.get('/api/user/device-status', authenticateToken, (req, res) => {
  const session = activeSockets.get(req.user.id);
  res.json({ connected: !!session, phoneNumber: session?.phoneNumber || null });
});

// ==================== WHATSAPP PAIRING ====================
let pendingPairing = new Map(); // userId -> { phoneNumber, timeout, resolve }

app.post('/api/connect/request', authenticateToken, async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return res.json({ success: false, message: 'Phone number required' });
  const normalized = phoneNumber.replace(/[^0-9]/g, '');
  // Check if already connected
  if (activeSockets.has(req.user.id)) {
    return res.json({ success: false, message: 'Already connected. Disconnect first.' });
  }
  // Start WhatsApp and wait for pairing code
  const sessionPath = path.join(SESSIONS_DIR, `session_${normalized}`);
  if (!fs.existsSync(sessionPath)) fs.mkdirSync(sessionPath, { recursive: true });
  try {
    const { version } = await fetchLatestBaileysVersion();
    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const logger = pino({ level: 'silent' });
    const sock = makeWASocket({
      version,
      logger,
      browser: Browsers.macOS('Chrome'),
      printQRInTerminal: false,
      auth: {
        creds: state.creds,
        keys: makeCacheableSignalKeyStore(state.keys, logger)
      },
      markOnlineOnConnect: false
    });
    sock.ev.on('creds.update', saveCreds);
    // Listen for pairing code
    const codePromise = new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(null), 60000);
      sock.ev.on('connection.update', async (update) => {
        if (update.qr) {
          // Not needed, we use requestPairingCode
        }
      });
      if (typeof sock.requestPairingCode === 'function') {
        sock.requestPairingCode(normalized).then(code => {
          clearTimeout(timeout);
          resolve(code);
        }).catch(() => resolve(null));
      } else {
        resolve(null);
      }
    });
    const code = await codePromise;
    if (!code) {
      sock.end();
      return res.json({ success: false, message: 'Failed to get pairing code' });
    }
    // Store pending connection
    pendingPairing.set(req.user.id, { phoneNumber: normalized, sock, code });
    // Wait for connection open
    const connectedPromise = new Promise((resolve) => {
      const timeout = setTimeout(() => resolve(false), 120000);
      sock.ev.on('connection.update', (update) => {
        if (update.connection === 'open') {
          clearTimeout(timeout);
          resolve(true);
          activeSockets.set(req.user.id, { sock, phoneNumber: normalized });
          // Update user record
          const users = readJSON(USERS_FILE);
          const index = users.findIndex(u => u.id === req.user.id);
          if (index !== -1) {
            users[index].phone = normalized;
            users[index].whatsappConnected = true;
            writeJSON(USERS_FILE, users);
          }
        }
      });
    });
    const connected = await connectedPromise;
    if (connected) {
      res.json({ success: true, code });
      pendingPairing.delete(req.user.id);
    } else {
      res.json({ success: false, message: 'Connection timeout' });
      sock.end();
      pendingPairing.delete(req.user.id);
    }
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: err.message });
  }
});

app.get('/api/connect/status', authenticateToken, (req, res) => {
  const session = activeSockets.get(req.user.id);
  res.json({ success: true, connected: !!session });
});

// ==================== BUGS (PLUGINS + DB) ====================
// Load plugins from bugs/ folder
const BUGS_FOLDER = path.join(__dirname, 'bugs');
let pluginBugs = [];
if (fs.existsSync(BUGS_FOLDER)) {
  const files = fs.readdirSync(BUGS_FOLDER).filter(f => f.endsWith('.js'));
  for (const file of files) {
    try {
      const bug = require(path.join(BUGS_FOLDER, file));
      if (bug.id && bug.execute) pluginBugs.push(bug);
    } catch (e) { console.error(`Failed to load bug ${file}:`, e); }
  }
}

function getAllBugs() {
  const dbBugs = readJSON(BUGS_FILE);
  return [...pluginBugs, ...dbBugs];
}

app.get('/api/bugs', authenticateToken, (req, res) => {
  const bugs = getAllBugs();
  res.json({ success: true, bugs });
});

app.post('/api/bugs/execute', authenticateToken, async (req, res) => {
  const { bugId, target } = req.body;
  if (!bugId || !target) return res.json({ success: false, message: 'Bug ID and target required' });
  const bugs = getAllBugs();
  const bug = bugs.find(b => b.id === bugId);
  if (!bug) return res.json({ success: false, message: 'Bug not found' });
  // Check premium
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  if (bug.premiumOnly && (!user || !user.premium)) {
    return res.json({ success: false, message: 'This bug requires premium account' });
  }
  // Get WhatsApp socket
  const session = activeSockets.get(req.user.id);
  if (!session || !session.sock) {
    return res.json({ success: false, message: 'WhatsApp not connected. Please connect first.' });
  }
  try {
    let result;
    if (bug.execute) {
      result = await bug.execute(session.sock, target, req.user.id);
    } else if (bug.code) {
      // For admin-added bugs (code stored as string)
      const fn = new Function('sock', 'target', 'userId', bug.code);
      result = await fn(session.sock, target, req.user.id);
    } else {
      return res.json({ success: false, message: 'Bug has no executable code' });
    }
    res.json({ success: true, message: result?.message || 'Executed successfully' });
  } catch (err) {
    console.error(err);
    res.json({ success: false, message: err.message });
  }
});

// ==================== FORGOT PASSWORD ====================
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (!user) return res.json({ success: false, message: 'Email not found' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 3600000; // 1 hour
  let tokens = readJSON(RESET_TOKENS_FILE);
  tokens = tokens.filter(t => t.email !== email);
  tokens.push({ email, token, expires });
  writeJSON(RESET_TOKENS_FILE, tokens);
  const resetLink = `http://localhost:${PORT}/reset-password.html?token=${token}`;
  // In production, send email. For now log to console.
  console.log(`Password reset link for ${email}: ${resetLink}`);
  res.json({ success: true, message: 'Reset link sent (check console)' });
});

app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.json({ success: false, message: 'Token and password required' });
  let tokens = readJSON(RESET_TOKENS_FILE);
  const entry = tokens.find(t => t.token === token && t.expires > Date.now());
  if (!entry) return res.json({ success: false, message: 'Invalid or expired token' });
  const users = readJSON(USERS_FILE);
  const userIndex = users.findIndex(u => u.email === entry.email);
  if (userIndex === -1) return res.json({ success: false, message: 'User not found' });
  users[userIndex].passwordHash = await bcrypt.hash(newPassword, 10);
  writeJSON(USERS_FILE, users);
  tokens = tokens.filter(t => t.token !== token);
  writeJSON(RESET_TOKENS_FILE, tokens);
  res.json({ success: true });
});

// ==================== ADMIN API ====================
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ success: true, token });
  } else {
    res.json({ success: false, message: 'Invalid admin password' });
  }
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const totalUsers = users.length;
  const approvedUsers = users.filter(u => u.approved).length;
  const premiumUsers = users.filter(u => u.premium).length;
  const connectedDevices = activeSockets.size;
  res.json({ success: true, totalUsers, approvedUsers, premiumUsers, connectedDevices });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const users = readJSON(USERS_FILE);
  const sanitized = users.map(u => ({ id: u.id, email: u.email, phone: u.phone, age: u.age, approved: u.approved, premium: u.premium, whatsappConnected: u.whatsappConnected }));
  res.json({ success: true, users: sanitized });
});

app.post('/api/admin/approve-user', adminAuth, (req, res) => {
  const { userId } = req.body;
  const users = readJSON(USERS_FILE);
  const index = users.findIndex(u => u.id === userId);
  if (index === -1) return res.json({ success: false, message: 'User not found' });
  users[index].approved = true;
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

app.post('/api/admin/toggle-premium', adminAuth, (req, res) => {
  const { userId, premium } = req.body;
  const users = readJSON(USERS_FILE);
  const index = users.findIndex(u => u.id === userId);
  if (index === -1) return res.json({ success: false, message: 'User not found' });
  users[index].premium = premium;
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

app.post('/api/admin/delete-user', adminAuth, (req, res) => {
  const { userId } = req.body;
  let users = readJSON(USERS_FILE);
  users = users.filter(u => u.id !== userId);
  writeJSON(USERS_FILE, users);
  activeSockets.delete(userId);
  // Optional: delete avatar file
  res.json({ success: true });
});

app.post('/api/admin/create-user', adminAuth, async (req, res) => {
  const { email, phone, age, password } = req.body;
  if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
  if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail allowed' });
  const users = readJSON(USERS_FILE);
  if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email exists' });
  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    id: crypto.randomUUID(),
    email,
    phone,
    age: parseInt(age),
    passwordHash: hashed,
    approved: true,
    premium: false,
    whatsappConnected: false,
    avatar: null,
    gender: 'Other',
    country: '',
    createdAt: new Date().toISOString()
  };
  users.push(newUser);
  writeJSON(USERS_FILE, users);
  res.json({ success: true });
});

app.get('/api/admin/bugs', adminAuth, (req, res) => {
  const bugs = getAllBugs();
  const simple = bugs.map(b => ({ id: b.id, name: b.name, category: b.category, description: b.description, premiumOnly: b.premiumOnly || false }));
  res.json({ success: true, bugs: simple });
});

app.post('/api/admin/add-bug', adminAuth, (req, res) => {
  const { name, category, description, targetPlaceholder, icon, premiumOnly, code } = req.body;
  if (!name || !category || !description || !code) return res.json({ success: false, message: 'Missing fields' });
  const newBug = {
    id: crypto.randomUUID(),
    name,
    category,
    description,
    targetPlaceholder: targetPlaceholder || 'Target ID',
    icon: icon || 'fas fa-bug',
    premiumOnly: !!premiumOnly,
    code
  };
  const dbBugs = readJSON(BUGS_FILE);
  dbBugs.push(newBug);
  writeJSON(BUGS_FILE, dbBugs);
  res.json({ success: true });
});

app.post('/api/admin/delete-bug', adminAuth, (req, res) => {
  const { bugId } = req.body;
  let dbBugs = readJSON(BUGS_FILE);
  dbBugs = dbBugs.filter(b => b.id !== bugId);
  writeJSON(BUGS_FILE, dbBugs);
  res.json({ success: true });
});

// Serve uploaded avatars
app.use('/uploads', express.static(UPLOADS_DIR));

// Fallback to index.html for client-side routing (if needed)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📁 Static files served from ./public`);
});
