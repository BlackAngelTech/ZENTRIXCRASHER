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
const SESSIONS_BASE = './auth_info_baileys'; // used by pairing routes
const QR_SESSIONS_BASE = './qr_sessions';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(SESSIONS_BASE)) fs.mkdirSync(SESSIONS_BASE, { recursive: true });
if (!fs.existsSync(QR_SESSIONS_BASE)) fs.mkdirSync(QR_SESSIONS_BASE, { recursive: true });

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

// ==================== USER ROUTES (Original) ====================
app.post('/api/register', async (req, res) => {
    const { email, phone, age, password } = req.body;
    if (!email || !phone || !age || !password) return res.json({ success: false, message: 'All fields required' });
    if (!/^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(email)) return res.json({ success: false, message: 'Only Gmail addresses allowed' });
    if (password.length < 6) return res.json({ success: false, message: 'Password min 6 chars' });
    const users = readJSON(USERS_FILE);
    if (users.find(u => u.email === email)) return res.json({ success: false, message: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
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
    // We can track connected sessions, but for now just return false
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

// ==================== BUGS PLUGINS (simplified) ====================
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
    if (bug.premiumOnly && (!user || !user.premium)) {
        return res.json({ success: false, message: 'This bug requires premium account' });
    }
    // For now, just simulate execution
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
    const premiumUsers = users.filter(u => u.premium).length;
    res.json({ success: true, totalUsers, approvedUsers, premiumUsers, connectedDevices: 0 });
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
        id: crypto.randomUUID ? crypto.randomUUID() : randomId(),
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

// ==================== PAIRING ROUTES (from pair.js and qr.js) ====================
const MAX_RECONNECT_ATTEMPTS = 3;
const SESSION_TIMEOUT = 5 * 60 * 1000;
const CLEANUP_DELAY = 5000;

async function removeFile(filePath) {
    try {
        if (!fs.existsSync(filePath)) return false;
        await fs.remove(filePath);
        return true;
    } catch (e) {
        return false;
    }
}

// /code endpoint (pairing code)
app.get('/code', async (req, res) => {
    let num = req.query.number;
    if (!num) return res.status(400).json({ error: 'Phone number is required' });
    num = num.replace(/[^0-9]/g, '');
    const phone = pn('+' + num);
    if (!phone.isValid()) return res.status(400).json({ error: 'Invalid phone number' });
    num = phone.getNumber('e164').replace('+', '');
    const sessionId = Date.now().toString() + Math.random().toString(36).substring(2, 9);
    const dirs = `${SESSIONS_BASE}/session_${sessionId}`;

    let pairingCodeSent = false;
    let sessionCompleted = false;
    let isCleaningUp = false;
    let responseSent = false;
    let reconnectAttempts = 0;
    let currentSocket = null;
    let timeoutHandle = null;

    async function cleanup(reason) {
        if (isCleaningUp) return;
        isCleaningUp = true;
        if (timeoutHandle) { clearTimeout(timeoutHandle); timeoutHandle = null; }
        if (currentSocket) {
            try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch (e) {}
            currentSocket = null;
        }
        setTimeout(async () => { await removeFile(dirs); }, CLEANUP_DELAY);
    }

    async function initiateSession() {
        if (sessionCompleted || isCleaningUp) return;
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            if (!responseSent && !res.headersSent) {
                responseSent = true;
                res.status(503).json({ error: 'Connection failed after multiple attempts' });
            }
            await cleanup('max_reconnects');
            return;
        }
        try {
            await fs.mkdir(dirs, { recursive: true });
            const { state, saveCreds } = await useMultiFileAuthState(dirs);
            const { version } = await fetchLatestBaileysVersion();
            if (currentSocket) {
                try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch (e) {}
            }
            currentSocket = makeWASocket({
                version,
                auth: {
                    creds: state.creds,
                    keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'fatal' }).child({ level: 'fatal' }))
                },
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
                    } catch (err) {
                        console.error('Error sending session message:', err.message);
                    } finally {
                        await cleanup('session_complete');
                    }
                }
                if (connection === 'close') {
                    if (sessionCompleted || isCleaningUp) { await cleanup('already_complete'); return; }
                    const statusCode = lastDisconnect?.error?.output?.statusCode;
                    if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                        if (!responseSent && !res.headersSent) {
                            responseSent = true;
                            res.status(401).json({ error: 'Invalid pairing code or session expired' });
                        }
                        await cleanup('logged_out');
                    } else if (pairingCodeSent && !sessionCompleted) {
                        reconnectAttempts++;
                        await delay(2000);
                        await initiateSession();
                    } else {
                        await cleanup('connection_closed');
                    }
                }
            });
            if (!sock.authState.creds.registered && !pairingCodeSent && !isCleaningUp) {
                await delay(1500);
                try {
                    pairingCodeSent = true;
                    let code = await sock.requestPairingCode(num, 'VECTORCRASHER');
                    code = code?.match(/.{1,4}/g)?.join('-') || code;
                    if (!responseSent && !res.headersSent) {
                        responseSent = true;
                        res.json({ code });
                    }
                } catch (error) {
                    pairingCodeSent = false;
                    if (!responseSent && !res.headersSent) {
                        responseSent = true;
                        res.status(503).json({ error: 'Failed to get pairing code' });
                    }
                    await cleanup('pairing_code_error');
                }
            }
            sock.ev.on('creds.update', saveCreds);
            timeoutHandle = setTimeout(async () => {
                if (!sessionCompleted && !isCleaningUp) {
                    if (!responseSent && !res.headersSent) {
                        responseSent = true;
                        res.status(408).json({ error: 'Pairing timeout' });
                    }
                    await cleanup('timeout');
                }
            }, SESSION_TIMEOUT);
        } catch (err) {
            console.error('Error initializing pair session:', err.message);
            if (!responseSent && !res.headersSent) {
                responseSent = true;
                res.status(503).json({ error: 'Service unavailable' });
            }
            await cleanup('init_error');
        }
    }
    await initiateSession();
});

// /qr endpoint (QR code)
app.get('/qr', async (req, res) => {
    const sessionId = `${Date.now()}${Math.random().toString(36).slice(2, 9)}`;
    const dirs = `${QR_SESSIONS_BASE}/session_${sessionId}`;
    await fs.mkdir(dirs, { recursive: true });

    let qrGenerated = false;
    let sessionCompleted = false;
    let responseSent = false;
    let reconnectAttempts = 0;
    let currentSocket = null;
    let timeoutHandle = null;
    let isCleaningUp = false;

    async function cleanup() {
        if (isCleaningUp) return;
        isCleaningUp = true;
        if (timeoutHandle) { clearTimeout(timeoutHandle); timeoutHandle = null; }
        if (currentSocket) {
            try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch {}
            currentSocket = null;
        }
        setTimeout(() => removeFile(dirs), 5000);
    }

    async function initiateSession() {
        if (sessionCompleted || isCleaningUp) return;
        if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
            if (!responseSent && !res.headersSent) {
                responseSent = true;
                res.status(503).json({ error: 'Connection failed after multiple attempts' });
            }
            await cleanup();
            return;
        }
        await fs.mkdir(dirs, { recursive: true });
        const { state, saveCreds } = await useMultiFileAuthState(dirs);
        try {
            const { version } = await fetchLatestBaileysVersion();
            if (currentSocket) {
                try { currentSocket.ev.removeAllListeners(); await currentSocket.end(); } catch {}
            }
            currentSocket = makeWASocket({
                version,
                logger: pino({ level: 'silent' }),
                browser: Browsers.ubuntu('Chrome'),
                auth: {
                    creds: state.creds,
                    keys: makeCacheableSignalKeyStore(state.keys, pino({ level: 'fatal' }).child({ level: 'fatal' }))
                },
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
                        const qrDataURL = await QRCode.toDataURL(qr, {
                            errorCorrectionLevel: 'M',
                            color: { dark: '#ffffff', light: '#0d1b2a' },
                            margin: 2
                        });
                        if (!responseSent && !res.headersSent) {
                            responseSent = true;
                            res.json({ qr: qrDataURL });
                        }
                    } catch (err) {
                        console.error('QR generation error:', err.message);
                        if (!responseSent && !res.headersSent) {
                            responseSent = true;
                            res.status(500).json({ error: 'Failed to generate QR code' });
                        }
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
                    } catch (err) {
                        console.error('Error sending session message:', err.message);
                    } finally {
                        await cleanup();
                    }
                }
                if (connection === 'close') {
                    if (sessionCompleted || isCleaningUp) { await cleanup(); return; }
                    const statusCode = lastDisconnect?.error?.output?.statusCode;
                    if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                        if (!responseSent && !res.headersSent) {
                            responseSent = true;
                            res.status(401).json({ error: 'Invalid QR scan or session expired' });
                        }
                        await cleanup();
                    } else if (qrGenerated && !sessionCompleted) {
                        reconnectAttempts++;
                        await delay(2000);
                        await initiateSession();
                    } else {
                        await cleanup();
                    }
                }
            });
            sock.ev.on('creds.update', saveCreds);
            timeoutHandle = setTimeout(async () => {
                if (!sessionCompleted && !isCleaningUp) {
                    if (!responseSent && !res.headersSent) {
                        responseSent = true;
                        res.status(408).json({ error: 'QR generation timeout' });
                    }
                    await cleanup();
                }
            }, 60000);
        } catch (err) {
            console.error('Error initializing QR session:', err.message);
            if (!responseSent && !res.headersSent) {
                responseSent = true;
                res.status(503).json({ error: 'Service unavailable' });
            }
            await cleanup();
        }
    }
    await initiateSession();
});

// Cleanup stale sessions periodically
setInterval(async () => {
    try {
        const now = Date.now();
        for (const base of [SESSIONS_BASE, QR_SESSIONS_BASE]) {
            if (!fs.existsSync(base)) continue;
            const sessions = await fs.readdir(base);
            for (const session of sessions) {
                try {
                    const stats = await fs.stat(`${base}/${session}`);
                    if (now - stats.mtimeMs > 10 * 60 * 1000) await fs.remove(`${base}/${session}`);
                } catch (e) {}
            }
        }
    } catch (e) {}
}, 60000);

// Serve uploads
app.use('/uploads', express.static(UPLOADS_DIR));

// Fallback
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Vector Crasher running on http://localhost:${PORT}`);
    console.log(`📁 Static files served from ./public`);
});
