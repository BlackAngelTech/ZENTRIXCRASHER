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

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// ==================== FILE STORAGE ====================
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const BUGS_FILE = path.join(DATA_DIR, 'bugs.json');
const RESET_TOKENS_FILE = path.join(DATA_DIR, 'reset_tokens.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const SESSIONS_BASE = './auth_info_baileys';
const QR_SESSIONS_BASE = './qr_sessions';

// Ensure directories exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(SESSIONS_BASE)) fs.mkdirSync(SESSIONS_BASE, { recursive: true });
if (!fs.existsSync(QR_SESSIONS_BASE)) fs.mkdirSync(QR_SESSIONS_BASE, { recursive: true });

// Initialize JSON files if not exist
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
if (!fs.existsSync(BUGS_FILE)) fs.writeFileSync(BUGS_FILE, JSON.stringify([]));
if (!fs.existsSync(RESET_TOKENS_FILE)) fs.writeFileSync(RESET_TOKENS_FILE, JSON.stringify([]));

const readJSON = (file) => JSON.parse(fs.readFileSync(file));
const writeJSON = (file, data) => fs.writeFileSync(file, JSON.stringify(data, null, 2));

// Helper: calculate remaining time
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
        // Check if token version matches (single session)
        const users = readJSON(USERS_FILE);
        const user = users.find(u => u.id === decoded.id);
        if (!user || user.tokenVersion !== decoded.tokenVersion) {
            return res.status(403).json({ success: false, message: 'Session expired elsewhere. Please login again.' });
        }
        // Check account expiration
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

// ==================== USER ROUTES ====================
app.post('/api/register', async (req, res) => {
    const { email, phone, age, password } = req.body;
    if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail addresses allowed' });
    if (password.length < 6) return res.json({ success: false, message: 'Password min 6 chars' });
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days trial
    const newUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
        email,
        phone,
        age: parseInt(age),
        passwordHash: hashedPassword,
        approved: false,           // needs admin approval
        tier: 'lite',              // lite, premium, ultimate
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
    if (user.expiresAt && new Date(user.expiresAt) < Date.now()) {
        return res.json({ success: false, message: 'Account expired. Contact admin to renew.' });
    }
    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) return res.json({ success: false, message: 'Invalid credentials' });
    
    // Increment tokenVersion to invalidate other sessions
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.lastLoginAt = new Date().toISOString();
    writeJSON(USERS_FILE, users);
    
    const expiresIn = remember ? '7d' : '1d';
    const token = jwt.sign(
        { id: user.id, email: user.email, role: 'user', tokenVersion: user.tokenVersion },
        JWT_SECRET,
        { expiresIn }
    );
    res.json({ success: true, token, tier: user.tier, expiresAt: user.expiresAt });
});

app.get('/api/user/status', authenticateToken, (req, res) => {
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (!user) return res.status(404).json({ success: false });
    res.json({
        success: true,
        premium: user.tier !== 'lite',
        tier: user.tier,
        expiresAt: user.expiresAt,
        remainingTime: getRemainingTime(user.expiresAt),
        approved: user.approved
    });
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
            tier: user.tier,
            expiresAt: user.expiresAt,
            remainingTime: getRemainingTime(user.expiresAt),
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

const upload = multer({ dest: UPLOADS_DIR, limits: { fileSize: 5 * 1024 * 1024 } });
app.post('/api/user/upload-avatar', authenticateToken, upload.single('avatar'), (req, res) => {
    if (!req.file) return res.json({ success: false, message: 'No file' });
    const ext = path.extname(req.file.originalname);
    const newPath = path.join(UPLOADS_DIR, `avatar_${req.user.id}${ext}`);
    fs.renameSync(req.file.path, newPath);
    const avatarUrl = `/uploads/avatar_${req.user.id}${ext}`;
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
    res.json({ success: true });
});

app.get('/api/user/device-status', authenticateToken, (req, res) => {
    // We can integrate with pairing sessions later, for now just return connected false
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
    console.log(`Password reset link for ${email}: ${resetLink}`);
    res.json({ success: true, message: 'Reset link sent (check console)' });
});

app.post('/api/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
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
    const users = readJSON(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    if (bug.premiumOnly && user.tier === 'lite') {
        return res.json({ success: false, message: 'This bug requires Premium or Ultimate tier' });
    }
    // For now, simulate execution
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
    const totalUsers = users.length;
    const approvedUsers = users.filter(u => u.approved).length;
    const premiumUsers = users.filter(u => u.tier !== 'lite').length;
    const liteUsers = users.filter(u => u.tier === 'lite').length;
    const expiredUsers = users.filter(u => u.expiresAt && new Date(u.expiresAt) < Date.now()).length;
    res.json({ success: true, totalUsers, approvedUsers, premiumUsers, liteUsers, expiredUsers, connectedDevices: 0 });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
    const users = readJSON(USERS_FILE);
    const sanitized = users.map(u => ({
        id: u.id, email: u.email, phone: u.phone, age: u.age,
        approved: u.approved, tier: u.tier, expiresAt: u.expiresAt,
        remaining: getRemainingTime(u.expiresAt),
        whatsappConnected: u.whatsappConnected
    }));
    res.json({ success: true, users: sanitized });
});

app.post('/api/admin/approve-user', adminAuth, (req, res) => {
    const { userId } = req.body;
    const users = readJSON(USERS_FILE);
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.json({ success: false, message: 'User not found' });
    users[index].approved = true;
    // Set trial expiration 30 days from now
    users[index].expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    writeJSON(USERS_FILE, users);
    res.json({ success: true });
});

app.post('/api/admin/update-tier', adminAuth, (req, res) => {
    const { userId, tier, daysToAdd } = req.body;
    const users = readJSON(USERS_FILE);
    const index = users.findIndex(u => u.id === userId);
    if (index === -1) return res.json({ success: false, message: 'User not found' });
    if (tier) users[index].tier = tier;
    if (daysToAdd && !isNaN(daysToAdd)) {
        const currentExpiry = users[index].expiresAt ? new Date(users[index].expiresAt) : new Date();
        const newExpiry = new Date(currentExpiry.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
        users[index].expiresAt = newExpiry.toISOString();
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
    const expiresAt = new Date(Date.now() + daysValid * 24 * 60 * 60 * 1000).toISOString();
    const newUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
        email,
        phone,
        age: parseInt(age),
        passwordHash: hashed,
        approved: true,
        tier,
        expiresAt,
        tokenVersion: 0,
        whatsappConnected: false,
        avatar: null,
        gender: 'Other',
        country: '',
        createdAt: new Date().toISOString(),
        lastLoginAt: null
    };
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
    const newBug = {
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
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

// ==================== PAIRING ROUTES (unchanged, but ensure they use latest code) ====================
// ... (keep the same `/code` and `/qr` routes from the previous full server.js)

// Fallback
app.use('/uploads', express.static(UPLOADS_DIR));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Vector Crasher running on http://localhost:${PORT}`);
    console.log(`📁 Static files served from ./public`);
});
