const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const crypto = require('crypto'); // ✅ Required for UUID generation

// Fallback for crypto.randomUUID (Node < 14.17)
if (!crypto.randomUUID) {
  crypto.randomUUID = () => {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = (crypto.randomBytes(1)[0] & 0xf) | 0;
      const v = c === 'x' ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  };
}

const {
  makeWASocket,
  useMultiFileAuthState,
  fetchLatestBaileysVersion,
  Browsers,
  DisconnectReason,
  makeCacheableSignalKeyStore
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vector_crasher_secret_key_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ZentrixTechOfficial';

// Serve static files from public/
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

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(BUGS_FILE)) fs.writeFileSync(BUGS_FILE, JSON.stringify([]));
if (!fs.existsSync(RESET_TOKENS_FILE)) fs.writeFileSync(RESET_TOKENS_FILE, JSON.stringify([]));

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

// ==================== WHATSAPP SESSIONS (Baileys 7.x) ====================
const activeSessions = new Map(); // userId -> { sock, phoneNumber, code, paired, sessionPath }

// Clean up old sessions on server restart
async function cleanupSessions() {
  for (const [userId, session] of activeSessions.entries()) {
    if (session.sock && !session.paired) {
      session.sock.end();
    }
  }
  activeSessions.clear();
}

// ==================== PAIRING ROUTES ====================
app.post('/api/connect/request', authenticateToken, async (req, res) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return res.json({ success: false, message: 'Phone number required' });
  const normalized = phoneNumber.replace(/\D/g, '');
  if (normalized.length < 10) return res.json({ success: false, message: 'Invalid phone number (min 10 digits)' });

  // Check if user already has an active paired connection
  const existing = activeSessions.get(req.user.id);
  if (existing && existing.paired) {
    return res.json({ success: false, message: 'Already connected. Please log out and back in if you need to change device.' });
  }

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
      markOnlineOnConnect: false,
      qrTimeout: 0 // disable QR
    });

    sock.ev.on('creds.update', saveCreds);

    // Listen for connection open to mark as paired
    const connectPromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Connection timeout after 2 minutes')), 120000);
      sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
          clearTimeout(timeout);
          const userData = activeSessions.get(req.user.id);
          if (userData) userData.paired = true;
          // Update user record in database
          const users = readJSON(USERS_FILE);
          const idx = users.findIndex(u => u.id === req.user.id);
          if (idx !== -1) {
            users[idx].phone = normalized;
            users[idx].whatsappConnected = true;
            writeJSON(USERS_FILE, users);
          }
          resolve(true);
        }
        if (connection === 'close') {
          const error = lastDisconnect?.error;
          if (error && !activeSessions.get(req.user.id)?.paired) reject(error);
        }
      });
    });

    // Request pairing code
    let code;
    try {
      code = await sock.requestPairingCode(normalized);
    } catch (err) {
      sock.end();
      return res.json({ success: false, message: `Failed to get pairing code: ${err.message}` });
    }

    // Store session
    activeSessions.set(req.user.id, {
      sock,
      phoneNumber: normalized,
      code,
      paired: false,
      sessionPath
    });

    // Start background connection check (don't wait for it)
    connectPromise.catch(err => console.error(`Pairing connection error for user ${req.user.id}:`, err));

    // Format code with dashes
    const formattedCode = code.match(/.{1,4}/g)?.join('-') || code;
    res.json({ success: true, code: formattedCode });
  } catch (err) {
    console.error('Pairing request error:', err);
    res.json({ success: false, message: err.message });
  }
});

app.get('/api/connect/status', authenticateToken, (req, res) => {
  const session = activeSessions.get(req.user.id);
  if (!session) return res.json({ success: true, connected: false });
  if (session.paired) return res.json({ success: true, connected: true, phoneNumber: session.phoneNumber });
  // Check if socket is already connected (e.g., after a reload)
  const isConnected = session.sock?.user ? true : false;
  if (isConnected) {
    session.paired = true;
    return res.json({ success: true, connected: true, phoneNumber: session.phoneNumber });
  }
  res.json({ success: true, connected: false });
});

// Optional: endpoint to disconnect (clean up)
app.post('/api/connect/disconnect', authenticateToken, async (req, res) => {
  const session = activeSessions.get(req.user.id);
  if (session && session.sock) {
    try {
      await session.sock.end();
    } catch (e) {}
    activeSessions.delete(req.user.id);
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx !== -1) {
      users[idx].whatsappConnected = false;
      writeJSON(USERS_FILE, users);
    }
  }
  res.json({ success: true });
});

// ==================== USER ROUTES ====================
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

app.get('/api/user/status', authenticateToken, (req, res) => {
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === req.user.id);
  res.json({ success: true, premium: user?.premium || false, approved: user?.approved || false });
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
  users = users.filter(u => u.id !== req.user.id);
  writeJSON(USERS_FILE, users);
  if (activeSessions.has(req.user.id)) {
    const sess = activeSessions.get(req.user.id);
    sess.sock?.end();
    activeSessions.delete(req.user.id);
  }
  res.json({ success: true });
});

app.get('/api/user/device-status', authenticateToken, (req, res) => {
  const session = activeSessions.get(req.user.id);
  res.json({ connected: !!(session && session.paired), phoneNumber: session?.phoneNumber || null });
});

// ==================== FORGOT PASSWORD ====================
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.email === email);
  if (!user) return res.json({ success: false, message: 'Email not found' });
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 3600000;
  let tokens = readJSON(RESET_TOKENS_FILE);
  tokens = tokens.filter(t => t.email !== email);
  tokens.push({ email, token, expires });
  writeJSON(RESET_TOKENS_FILE, tokens);
  const resetLink = `http://localhost:${PORT}/reset-password.html?token=${token}`;
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

// ==================== BUGS & PLUGINS ====================
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
  const bugs = getAllBugs().map(b => ({
    id: b.id,
    name: b.name,
    category: b.category,
    description: b.description,
    targetPlaceholder: b.targetPlaceholder,
    icon: b.icon,
    premiumOnly: b.premiumOnly || false
  }));
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
  const session = activeSessions.get(req.user.id);
  if (!session || !session.paired || !session.sock) {
    return res.json({ success: false, message: 'WhatsApp not connected. Please connect first.' });
  }
  try {
    let result;
    if (bug.execute) {
      result = await bug.execute(session.sock, target, req.user.id);
    } else if (bug.code) {
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
  const connectedDevices = Array.from(activeSessions.values()).filter(s => s.paired).length;
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
  if (activeSessions.has(userId)) {
    const sess = activeSessions.get(userId);
    sess.sock?.end();
    activeSessions.delete(userId);
  }
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
  const bugs = getAllBugs().map(b => ({ id: b.id, name: b.name, category: b.category, description: b.description, premiumOnly: b.premiumOnly || false }));
  res.json({ success: true, bugs });
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

// Fallback to index.html for client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Cleanup on exit
process.on('SIGINT', async () => {
  for (const [_, sess] of activeSessions) {
    if (sess.sock) await sess.sock.end();
  }
  process.exit(0);
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`📁 Static files served from ./public`);
});
