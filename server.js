import express from 'express';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs-extra';
import pino from 'pino';
import QRCode from 'qrcode';
import pn from 'awesome-phonenumber';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import crypto from 'crypto';
import {
    makeWASocket,
    useMultiFileAuthState,
    delay,
    makeCacheableSignalKeyStore,
    Browsers,
    jidNormalizedUser,
    fetchLatestBaileysVersion,
    DisconnectReason
} from '@itsliaaa/baileys';
import cors from 'cors';
import { encodeSession, randomId } from './session.js';
import { sendSessionMessage } from './lib/message.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'vector_crasher_secret_key_change_me';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'ZentrixTechOfficial';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== FILE STORAGE ====================
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const BUGS_FILE = path.join(DATA_DIR, 'bugs.json');
const RESET_TOKENS_FILE = path.join(DATA_DIR, 'reset_tokens.json');
const CHANNELS_FILE = path.join(DATA_DIR, 'channels.json');
const GROUPS_FILE = path.join(DATA_DIR, 'groups.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const CHAT_MEDIA_DIR = path.join(__dirname, 'chat_media');
const SESSIONS_BASE = './auth_info_baileys';
const QR_SESSIONS_BASE = './qr_sessions';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(CHAT_MEDIA_DIR)) fs.mkdirSync(CHAT_MEDIA_DIR, { recursive: true });
if (!fs.existsSync(SESSIONS_BASE)) fs.mkdirSync(SESSIONS_BASE, { recursive: true });
if (!fs.existsSync(QR_SESSIONS_BASE)) fs.mkdirSync(QR_SESSIONS_BASE, { recursive: true });

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(BUGS_FILE)) fs.writeFileSync(BUGS_FILE, JSON.stringify([]));
if (!fs.existsSync(RESET_TOKENS_FILE)) fs.writeFileSync(RESET_TOKENS_FILE, JSON.stringify([]));
if (!fs.existsSync(CHANNELS_FILE)) fs.writeFileSync(CHANNELS_FILE, JSON.stringify([]));
if (!fs.existsSync(GROUPS_FILE)) fs.writeFileSync(GROUPS_FILE, JSON.stringify([]));
if (!fs.existsSync(MESSAGES_FILE)) fs.writeFileSync(MESSAGES_FILE, JSON.stringify([]));

const readJSON = (file) => JSON.parse(fs.readFileSync(file));
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

function getRemainingTime(expiresAt) {
    if (!expiresAt) return null;
    const remaining = new Date(expiresAt) - Date.now();
    if (remaining <= 0) return 'Expired';
    const days = Math.floor(remaining / (1000 * 60 * 60 * 24));
    const hours = Math.floor((remaining % (86400000)) / (1000 * 60 * 60));
    const minutes = Math.floor((remaining % (3600000)) / (1000 * 60));
    if (days > 0) return `${days}d ${hours}h`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
}

// ==================== AUTH MIDDLEWARE ====================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: 'Unauthorized' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === decoded.id);
        if (!user || user.tokenVersion !== decoded.tokenVersion) {
            return res.status(403).json({ success: false, message: 'Session expired elsewhere. Please login again.' });
        }
        if (user.expiresAt && new Date(user.expiresAt) < Date.now()) {
            return res.status(403).json({ success: false, message: 'Account expired. Contact admin to renew.' });
        }
        req.user = decoded;
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

// ==================== USER ROUTES (same as before) ====================
app.post('/api/register', async (req, res) => {
    const { email, phone, age, password } = req.body;
    if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail addresses allowed' });
    if (password.length < 6) return res.json({ success: false, message: 'Password min 6 chars' });
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    const newUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
        email,
        phone,
        age: parseInt(age),
        passwordHash: hashedPassword,
        approved: false,
        tier: 'lite',
        expiresAt: expiresAt.toISOString(),
        tokenVersion: 0,
        whatsappConnected: false,
        avatar: null,
        gender: 'Other',
        country: '',
        createdAt: now.toISOString(),
        lastLoginAt: null
    };
    users.push(newUser);
    writeJSON(USERS_FILE, users);
    res.json({ success: true, message: 'Registration pending admin approval (30-day trial starts after approval)' });
});

app.post('/api/login', async (req, res) => {
    const { email, password, remember } = req.body;
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.email === email);
    if (!user) return res.json({ success: false, message: 'Invalid credentials' });
    if (!user.approved) return res.json({ success: false, message: 'Account pending approval', pendingApproval: true });
    if (user.expiresAt && new Date(user.expiresAt) < Date.now()) return res.json({ success: false, message: 'Account expired' });
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.json({ success: false, message: 'Invalid credentials' });
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.lastLoginAt = new Date().toISOString();
    writeJSON(USERS_FILE, users);
    const expiresIn = remember ? '7d' : '1d';
    const token = jwt.sign({ id: user.id, email: user.email, role: 'user', tokenVersion: user.tokenVersion }, JWT_SECRET, { expiresIn });
    res.json({ success: true, token, tier: user.tier, expiresAt: user.expiresAt });
});

app.get('/api/user/status', authenticateToken, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    res.json({ success: true, premium: user.tier !== 'lite', tier: user.tier, expiresAt: user.expiresAt, remainingTime: getRemainingTime(user.expiresAt), approved: user.approved });
});

app.get('/api/user/profile', authenticateToken, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    res.json({ success: true, user: { email: user.email, phone: user.phone, age: user.age, gender: user.gender, country: user.country, avatar: user.avatar, approved: user.approved, tier: user.tier, expiresAt: user.expiresAt, remainingTime: getRemainingTime(user.expiresAt), whatsappConnected: user.whatsappConnected } });
});

app.post('/api/user/update-profile', authenticateToken, (req, res) => {
    const { age, gender, country, phone } = req.body;
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx === -1) return res.json({ success: false, message: 'User not found' });
    if (age && (age < 13 || age > 100)) return res.json({ success: false, message: 'Invalid age' });
    if (phone && !/^\+?\d{10,15}$/.test(phone.replace(/\s/g, ''))) return res.json({ success: false, message: 'Invalid phone' });
    if (age) users[idx].age = parseInt(age);
    if (gender) users[idx].gender = gender;
    if (country) users[idx].country = country;
    if (phone) users[idx].phone = phone;
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

const uploadAvatar = multer({ dest: UPLOADS_DIR, limits: { fileSize: 5 * 1024 * 1024 } });
app.post('/api/user/upload-avatar', authenticateToken, uploadAvatar.single('avatar'), (req, res) => {
    if (!req.file) return res.json({ success: false, message: 'No file' });
    const ext = path.extname(req.file.originalname);
    const newPath = path.join(UPLOADS_DIR, `avatar_${req.user.id}${ext}`);
    fs.renameSync(req.file.path, newPath);
    const avatarUrl = `/uploads/avatar_${req.user.id}${ext}`;
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === req.user.id);
    if (idx !== -1) users[idx].avatar = avatarUrl;
    writeJSON(USERS_FILE, users);
    res.json({ success: true, avatarUrl });
});

app.post('/api/user/delete-account', authenticateToken, (req, res) => {
    let users = readJSON(USERS_FILE);
    users = users.filter(u => u.id !== req.user.id);
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});

app.get('/api/user/device-status', authenticateToken, (req, res) => {
    res.json({ connected: false, phoneNumber: null });
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
    console.log(`Reset link for ${email}: ${resetLink}`);
    res.json({ success: true, message: 'Reset link sent (check console)' });
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    let tokens = readJSON(RESET_TOKENS_FILE);
    const entry = tokens.find(t => t.token === token && t.expires > Date.now());
    if (!entry) return res.json({ success: false, message: 'Invalid token' });
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.email === entry.email);
    if (idx === -1) return res.json({ success: false, message: 'User not found' });
    users[idx].passwordHash = await bcrypt.hash(newPassword, 10);
    writeJSON(USERS_FILE, users);
    tokens = tokens.filter(t => t.token !== token);
    writeJSON(RESET_TOKENS_FILE, tokens);
    res.json({ success: true });
});

// ==================== BUGS (simplified) ====================
const BUGS_FOLDER = path.join(__dirname, 'bugs');
let pluginBugs = [];
if (fs.existsSync(BUGS_FOLDER)) {
    const files = fs.readdirSync(BUGS_FOLDER).filter(f => f.endsWith('.js'));
    for (const file of files) {
        try {
            const bug = await import(path.join(BUGS_FOLDER, file));
            if (bug.id && bug.execute) pluginBugs.push(bug);
        } catch (e) { console.error(`Failed to load bug ${file}:`, e); }
    }
}
function getAllBugs() {
    const dbBugs = readJSON(BUGS_FILE);
    return [...pluginBugs, ...dbBugs];
}
app.get('/api/bugs', authenticateToken, (req, res) => {
    const bugs = getAllBugs().map(b => ({ id: b.id, name: b.name, category: b.category, description: b.description, targetPlaceholder: b.targetPlaceholder, icon: b.icon, premiumOnly: b.premiumOnly || false }));
    res.json({ success: true, bugs });
});
app.post('/api/bugs/execute', authenticateToken, async (req, res) => {
    const { bugId, target } = req.body;
    const bugs = getAllBugs();
    const bug = bugs.find(b => b.id === bugId);
    if (!bug) return res.json({ success: false, message: 'Bug not found' });
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (bug.premiumOnly && user.tier === 'lite') return res.json({ success: false, message: 'Premium only' });
    res.json({ success: true, message: `Bug ${bug.name} executed on ${target} (simulated)` });
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
    res.json({ success: true, totalUsers: users.length, approvedUsers: users.filter(u => u.approved).length, premiumUsers: users.filter(u => u.tier !== 'lite').length, connectedDevices: 0 });
});
app.get('/api/admin/users', adminAuth, (req, res) => {
    const users = readJSON(USERS_FILE);
    res.json({ success: true, users: users.map(u => ({ id: u.id, email: u.email, phone: u.phone, age: u.age, approved: u.approved, premium: u.tier !== 'lite', whatsappConnected: u.whatsappConnected })) });
});
app.post('/api/admin/approve-user', adminAuth, (req, res) => {
    const { userId } = req.body;
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return res.json({ success: false, message: 'User not found' });
    users[idx].approved = true;
    users[idx].expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});
app.post('/api/admin/update-tier', adminAuth, (req, res) => {
    const { userId, tier, daysToAdd } = req.body;
    const users = readJSON(USERS_FILE);
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return res.json({ success: false, message: 'User not found' });
    if (tier) users[idx].tier = tier;
    if (daysToAdd) {
        const newExpiry = new Date(users[idx].expiresAt ? new Date(users[idx].expiresAt).getTime() + daysToAdd * 86400000 : Date.now() + daysToAdd * 86400000);
        users[idx].expiresAt = newExpiry.toISOString();
    }
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});
app.post('/api/admin/delete-user', adminAuth, (req, res) => {
    const { userId } = req.body;
    let users = readJSON(USERS_FILE);
    users = users.filter(u => u.id !== userId);
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});
app.post('/api/admin/create-user', adminAuth, async (req, res) => {
    const { email, phone, age, password, tier = 'lite', daysValid = 30 } = req.body;
    if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail allowed' });
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email exists' });
    const hashed = await bcrypt.hash(password, 10);
    const expiresAt = new Date(Date.now() + daysValid * 86400000).toISOString();
    const newUser = { id: crypto.randomUUID(), email, phone, age: parseInt(age), passwordHash: hashed, approved: true, tier, expiresAt, tokenVersion: 0, whatsappConnected: false, avatar: null, gender: 'Other', country: '', createdAt: new Date().toISOString(), lastLoginAt: null };
    users.push(newUser);
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});
app.get('/api/admin/bugs', adminAuth, (req, res) => {
    const bugs = getAllBugs().map(b => ({ id: b.id, name: b.name, category: b.category, premiumOnly: b.premiumOnly || false }));
    res.json({ success: true, bugs });
});
app.post('/api/admin/add-bug', adminAuth, (req, res) => {
    const { name, category, description, targetPlaceholder, icon, premiumOnly, code } = req.body;
    if (!name || !category || !description || !code) return res.json({ success: false, message: 'Missing fields' });
    const bugs = readJSON(BUGS_FILE);
    bugs.push({ id: crypto.randomUUID(), name, category, description, targetPlaceholder: targetPlaceholder || 'Target ID', icon: icon || 'fas fa-bug', premiumOnly: !!premiumOnly, code });
    writeJSON(BUGS_FILE, bugs);
    res.json({ success: true });
});
app.post('/api/admin/delete-bug', adminAuth, (req, res) => {
    const { bugId } = req.body;
    let bugs = readJSON(BUGS_FILE);
    bugs = bugs.filter(b => b.id !== bugId);
    writeJSON(BUGS_FILE, bugs);
    res.json({ success: true });
});

// ==================== BROADCAST ====================
app.post('/api/admin/broadcast', adminAuth, async (req, res) => {
    const { message, target } = req.body;
    if (!message) return res.json({ success: false, message: 'Message required' });
    const users = readJSON(USERS_FILE);
    let recipients = users;
    if (target === 'approved') recipients = users.filter(u => u.approved);
    else if (target === 'premium') recipients = users.filter(u => u.tier !== 'lite');
    // Simulate sending (in real app, you'd send via WhatsApp socket or store in inbox)
    // For now, we just log and return count.
    console.log(`Broadcast to ${recipients.length} users: ${message}`);
    res.json({ success: true, count: recipients.length });
});

// ==================== CHANNELS ====================
app.get('/api/channels', authenticateToken, (req, res) => {
    const channels = readJSON(CHANNELS_FILE);
    res.json({ success: true, channels: channels.map(ch => ({ id: ch.id, name: ch.name, description: ch.description })) });
});
app.post('/api/admin/create-channel', adminAuth, (req, res) => {
    const { name, description } = req.body;
    const channels = readJSON(CHANNELS_FILE);
    channels.push({ id: crypto.randomUUID(), name, description, createdAt: new Date().toISOString() });
    writeJSON(CHANNELS_FILE, channels);
    res.json({ success: true });
});
app.post('/api/admin/delete-channel', adminAuth, (req, res) => {
    const { channelId } = req.body;
    let channels = readJSON(CHANNELS_FILE);
    channels = channels.filter(c => c.id !== channelId);
    writeJSON(CHANNELS_FILE, channels);
    res.json({ success: true });
});

// ==================== GROUPS ====================
app.get('/api/groups', authenticateToken, (req, res) => {
    let groups = readJSON(GROUPS_FILE);
    const myGroups = groups.filter(g => g.members.includes(req.user.id) || g.creator === req.user.id);
    res.json({ success: true, groups: myGroups.map(g => ({ id: g.id, name: g.name, premium: g.premium || false, creator: g.creator, membersCount: g.members.length })) });
});
app.post('/api/admin/create-group', adminAuth, (req, res) => {
    const { name, premium } = req.body;
    const groups = readJSON(GROUPS_FILE);
    groups.push({ id: crypto.randomUUID(), name, premium: !!premium, creator: req.admin.id, members: [req.admin.id], createdAt: new Date().toISOString() });
    writeJSON(GROUPS_FILE, groups);
    res.json({ success: true });
});
app.post('/api/admin/delete-group', adminAuth, (req, res) => {
    const { groupId } = req.body;
    let groups = readJSON(GROUPS_FILE);
    groups = groups.filter(g => g.id !== groupId);
    writeJSON(GROUPS_FILE, groups);
    res.json({ success: true });
});
app.post('/api/create-group', authenticateToken, (req, res) => {
    const { name } = req.body;
    const groups = readJSON(GROUPS_FILE);
    groups.push({ id: crypto.randomUUID(), name, premium: false, creator: req.user.id, members: [req.user.id], createdAt: new Date().toISOString() });
    writeJSON(GROUPS_FILE, groups);
    res.json({ success: true });
});
app.post('/api/join-group', authenticateToken, (req, res) => {
    const { groupId } = req.body;
    const groups = readJSON(GROUPS_FILE);
    const group = groups.find(g => g.id === groupId);
    if (!group) return res.json({ success: false, message: 'Group not found' });
    if (!group.members.includes(req.user.id)) group.members.push(req.user.id);
    writeJSON(GROUPS_FILE, groups);
    res.json({ success: true });
});
app.post('/api/leave-group', authenticateToken, (req, res) => {
    const { groupId } = req.body;
    const groups = readJSON(GROUPS_FILE);
    const group = groups.find(g => g.id === groupId);
    if (group && group.members.includes(req.user.id)) group.members = group.members.filter(m => m !== req.user.id);
    writeJSON(GROUPS_FILE, groups);
    res.json({ success: true });
});

// ==================== MESSAGING (text & media) ====================
const chatMediaUpload = multer({ dest: CHAT_MEDIA_DIR, limits: { fileSize: 25 * 1024 * 1024 } });
app.post('/api/upload-chat-media', authenticateToken, chatMediaUpload.single('media'), (req, res) => {
    if (!req.file) return res.json({ success: false, message: 'No file' });
    const ext = path.extname(req.file.originalname);
    const filename = `${Date.now()}_${Math.random().toString(36).substring(2, 8)}${ext}`;
    const newPath = path.join(CHAT_MEDIA_DIR, filename);
    fs.renameSync(req.file.path, newPath);
    const url = `/chat_media/${filename}`;
    res.json({ success: true, url });
});

app.get('/api/messages', authenticateToken, (req, res) => {
    const { chatType, chatId } = req.query;
    if (!chatType || !chatId) return res.json({ success: false, message: 'Missing chatType or chatId' });
    const messages = readJSON(MESSAGES_FILE);
    const filtered = messages.filter(m => m.chatType === chatType && m.chatId === chatId).sort((a,b) => a.timestamp - b.timestamp);
    const users = readJSON(USERS_FILE);
    const enriched = filtered.map(m => {
        const sender = users.find(u => u.id === m.senderId);
        return { ...m, senderName: sender ? sender.email.split('@')[0] : 'Unknown' };
    });
    res.json({ success: true, messages: enriched });
});

app.post('/api/send-message', authenticateToken, (req, res) => {
    const { chatType, chatId, text, mediaUrl } = req.body;
    if (!chatType || !chatId) return res.json({ success: false, message: 'Missing chatType or chatId' });
    if (!text && !mediaUrl) return res.json({ success: false, message: 'No content' });
    const messages = readJSON(MESSAGES_FILE);
    const newMsg = {
        id: crypto.randomUUID(),
        chatType,
        chatId,
        senderId: req.user.id,
        text: text || '',
        mediaUrl: mediaUrl || null,
        timestamp: Date.now()
    };
    messages.push(newMsg);
    writeJSON(MESSAGES_FILE, messages);
    res.json({ success: true });
});

// Serve chat media
app.use('/chat_media', express.static(CHAT_MEDIA_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

// ==================== PAIRING ROUTES (same as previous working version) ====================
const MAX_RECONNECT_ATTEMPTS = 3;
const SESSION_TIMEOUT = 5 * 60 * 1000;
const CLEANUP_DELAY = 5000;
async function removeFile(filePath) {
    try { if (fs.existsSync(filePath)) await fs.remove(filePath); return true; } catch(e) { return false; }
}
app.get('/code', async (req, res) => {
    let num = req.query.number;
    if (!num) return res.status(400).json({ error: 'Phone number required' });
    num = num.replace(/[^0-9]/g, '');
    const phone = pn('+' + num);
    if (!phone.isValid()) return res.status(400).json({ error: 'Invalid phone number' });
    num = phone.getNumber('e164').replace('+', '');
    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2,9);
    const dirs = `${SESSIONS_BASE}/session_${sessionId}`;
    let pairingCodeSent = false, sessionCompleted = false, isCleaningUp = false, responseSent = false, reconnectAttempts = 0, currentSocket = null, timeoutHandle = null;
    async function cleanup() {
        if (isCleaningUp) return;
        isCleaningUp = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (currentSocket) { try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch(e) {} }
        setTimeout(() => removeFile(dirs), CLEANUP_DELAY);
    }
    async function initiateSession() {
        if (sessionCompleted || isCleaningUp) return;
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            if (!responseSent && !res.headersSent) { responseSent = true; res.status(503).json({ error: 'Connection failed' }); }
            await cleanup();
            return;
        }
        await fs.mkdir(dirs, { recursive: true });
        const { state, saveCreds } = await useMultiFileAuthState(dirs);
        const { version } = await fetchLatestBaileysVersion();
        if (currentSocket) try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch(e) {}
        currentSocket = makeWASocket({
            version,
            auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'fatal' }).child({ level: 'fatal' })) },
            printQRInTerminal: false,
            logger: pino({ level: 'silent' }),
            browser: Browsers.ubuntu('Chrome'),
            markOnlineOnConnect: false,
            generateHighQualityLinkPreview: false,
            defaultQueryTimeoutMs: 60000,
            connectTimeoutMs: 60000,
            keepAliveIntervalMs: 30000,
            retryRequestDelayMs: 250,
            maxRetries: 3
        });
        const sock = currentSocket;
        sock.ev.on('connection.update', async (update) => {
            if (isCleaningUp) return;
            const { connection, lastDisconnect } = update;
            if (connection === 'open') {
                if (sessionCompleted) return;
                sessionCompleted = true;
                try {
                    const credsFile = `${dirs}/creds.json`;
                    if (fs.existsSync(credsFile)) {
                        const credsBuffer = await fs.readFile(credsFile);
                        const sageSession = encodeSession(credsBuffer);
                        const userJid = jidNormalizedUser(num + '@s.whatsapp.net');
                        await sendSessionMessage(sock, userJid, sageSession);
                        await delay(1000);
                    }
                } catch(err) { console.error(err); }
                finally { await cleanup(); }
            }
            if (connection === 'close') {
                if (sessionCompleted || isCleaningUp) { await cleanup(); return; }
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                    if (!responseSent && !res.headersSent) { responseSent = true; res.status(401).json({ error: 'Invalid pairing code' }); }
                    await cleanup();
                } else if (pairingCodeSent && !sessionCompleted) {
                    reconnectAttempts++;
                    await delay(2000);
                    await initiateSession();
                } else { await cleanup(); }
            }
        });
        if (!sock.authState.creds.registered && !pairingCodeSent && !isCleaningUp) {
            await delay(1500);
            try {
                pairingCodeSent = true;
                let code = await sock.requestPairingCode(num, 'VECTORCRASHER');
                code = code?.match(/.{1,4}/g)?.join('-') || code;
                if (!responseSent && !res.headersSent) { responseSent = true; res.json({ code }); }
            } catch(err) {
                pairingCodeSent = false;
                if (!responseSent && !res.headersSent) { responseSent = true; res.status(503).json({ error: 'Failed to get code' }); }
                await cleanup();
            }
        }
        sock.ev.on('creds.update', saveCreds);
        timeoutHandle = setTimeout(async () => {
            if (!sessionCompleted && !isCleaningUp) {
                if (!responseSent && !res.headersSent) { responseSent = true; res.status(408).json({ error: 'Timeout' }); }
                await cleanup();
            }
        }, SESSION_TIMEOUT);
    }
    await initiateSession();
});
app.get('/qr', async (req, res) => {
    const sessionId = `${Date.now()}${Math.random().toString(36).slice(2,9)}`;
    const dirs = `${QR_SESSIONS_BASE}/session_${sessionId}`;
    let qrGenerated = false, sessionCompleted = false, responseSent = false, reconnectAttempts = 0, currentSocket = null, timeoutHandle = null, isCleaningUp = false;
    async function cleanup() {
        if (isCleaningUp) return;
        isCleaningUp = true;
        if (timeoutHandle) clearTimeout(timeoutHandle);
        if (currentSocket) { try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch(e) {} }
        setTimeout(() => removeFile(dirs), 5000);
    }
    async function initiateSession() {
        if (sessionCompleted || isCleaningUp) return;
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            if (!responseSent && !res.headersSent) { responseSent = true; res.status(503).json({ error: 'Connection failed' }); }
            await cleanup();
            return;
        }
        await fs.mkdir(dirs, { recursive: true });
        const { state, saveCreds } = await useMultiFileAuthState(dirs);
        const { version } = await fetchLatestBaileysVersion();
        if (currentSocket) try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch(e) {}
        currentSocket = makeWASocket({
            version,
            logger: pino({ level: 'silent' }),
            browser: Browsers.ubuntu('Chrome'),
            auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'fatal' }).child({ level: 'fatal' })) },
            printQRInTerminal: false,
            markOnlineOnConnect: false,
            generateHighQualityLinkPreview: false,
            defaultQueryTimeoutMs: 60000,
            connectTimeoutMs: 60000,
            keepAliveIntervalMs: 30000,
            retryRequestDelayMs: 250,
            maxRetries: 3
        });
        const sock = currentSocket;
        sock.ev.on('connection.update', async (update) => {
            if (isCleaningUp) return;
            const { connection, lastDisconnect, qr } = update;
            if (qr && !qrGenerated && !sessionCompleted) {
                qrGenerated = true;
                try {
                    const qrDataURL = await QRCode.toDataURL(qr, { errorCorrectionLevel: 'M', color: { dark: '#ffffff', light: '#0d1b2a' }, margin: 2 });
                    if (!responseSent && !res.headersSent) { responseSent = true; res.json({ qr: qrDataURL }); }
                } catch(err) {
                    if (!responseSent && !res.headersSent) { responseSent = true; res.status(500).json({ error: 'QR generation failed' }); }
                    await cleanup();
                }
            }
            if (connection === 'open') {
                if (sessionCompleted) return;
                sessionCompleted = true;
                try {
                    const credsFile = `${dirs}/creds.json`;
                    if (fs.existsSync(credsFile)) {
                        const credsBuffer = await fs.readFile(credsFile);
                        const sageSession = encodeSession(credsBuffer);
                        const userJid = jidNormalizedUser(sock.authState.creds.me.id);
                        await sendSessionMessage(sock, userJid, sageSession);
                        await delay(1000);
                    }
                } catch(err) { console.error(err); }
                finally { await cleanup(); }
            }
            if (connection === 'close') {
                if (sessionCompleted || isCleaningUp) { await cleanup(); return; }
                const statusCode = lastDisconnect?.error?.output?.statusCode;
                if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                    if (!responseSent && !res.headersSent) { responseSent = true; res.status(401).json({ error: 'Invalid QR scan' }); }
                    await cleanup();
                } else if (qrGenerated && !sessionCompleted) {
                    reconnectAttempts++;
                    await delay(2000);
                    await initiateSession();
                } else { await cleanup(); }
            }
        });
        sock.ev.on('creds.update', saveCreds);
        timeoutHandle = setTimeout(async () => {
            if (!sessionCompleted && !isCleaningUp) {
                if (!responseSent && !res.headersSent) { responseSent = true; res.status(408).json({ error: 'Timeout' }); }
                await cleanup();
            }
        }, 60000);
    }
    await initiateSession();
});

// Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Vector Crasher running on http://localhost:${PORT}`);
    console.log(`📁 Static files served from ./public`);
});
