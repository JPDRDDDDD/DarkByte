const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs/promises');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 5501);
const SESSION_COOKIE = 'db_sid';
const OWNER_EMAIL = 'davifeitoza137@gmail.com';
const ROLE_OWNER = 'owner';
const ROLE_CO_OWNER = 'co-owner';
const ROLE_ATTENDANT = 'atendente';
const ROLE_CLIENT = 'cliente';
const ALLOWED_ROLES = new Set([ROLE_OWNER, ROLE_CO_OWNER, ROLE_ATTENDANT, ROLE_CLIENT]);
const SESSION_TTL_MS = 1000 * 60 * 60 * 12;
const CAPTCHA_TTL_MS = 1000 * 60 * 3;
const LOGIN_LOCK_MS = 1000 * 60 * 15;
const MAX_LOGIN_ATTEMPTS = 5;

const sessions = new Map();
const captchaStore = new Map();
const loginGuard = new Map();

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(express.json({ limit: '200kb' }));
app.use(cookieParser());
app.use(express.static(__dirname));

function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}

function normalizeRole(role) {
    const normalized = String(role || '').trim().toLowerCase();
    if (ALLOWED_ROLES.has(normalized)) return normalized;
    return ROLE_CLIENT;
}

function isAdminRole(role) {
    return role === ROLE_OWNER || role === ROLE_CO_OWNER;
}

function isStrongPassword(password) {
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z\d]).{8,}$/;
    return regex.test(String(password || ''));
}

function createCaptcha(mode = 'login') {
    const isSignup = mode === 'signup';
    const a = isSignup ? randomInt(3, 15) : randomInt(10, 30);
    const b = isSignup ? randomInt(1, 9) : randomInt(2, 7);
    const operator = isSignup ? '+' : '-';
    const answer = isSignup ? a + b : a - b;
    const token = crypto.randomUUID();
    captchaStore.set(token, {
        answer,
        createdAt: Date.now()
    });
    return {
        captchaToken: token,
        question: `Captcha: quanto e ${a} ${operator} ${b}?`
    };
}

function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

async function ensureUsersFile() {
    await fs.mkdir(DATA_DIR, { recursive: true });
    try {
        await fs.access(USERS_FILE);
    } catch {
        await fs.writeFile(USERS_FILE, JSON.stringify({}, null, 2), 'utf8');
    }
}

async function readUsers() {
    await ensureUsersFile();
    const raw = await fs.readFile(USERS_FILE, 'utf8');
    try {
        const parsed = JSON.parse(raw);
        if (parsed[OWNER_EMAIL]) {
            parsed[OWNER_EMAIL].role = ROLE_OWNER;
        }
        return parsed;
    } catch {
        return {};
    }
}

async function saveUsers(users) {
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

async function hashSecret(plain) {
    const salt = crypto.randomBytes(16).toString('base64');
    const derived = await scrypt(plain, salt);
    return `scrypt$${salt}$${derived.toString('base64')}`;
}

async function verifySecret(plain, packedHash) {
    const parts = String(packedHash || '').split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
    const [, salt, expectedB64] = parts;
    const expected = Buffer.from(expectedB64, 'base64');
    const actual = await scrypt(plain, salt);
    if (expected.length !== actual.length) return false;
    return crypto.timingSafeEqual(expected, actual);
}

function scrypt(value, salt) {
    return new Promise((resolve, reject) => {
        crypto.scrypt(String(value || ''), salt, 64, (err, key) => {
            if (err) reject(err);
            else resolve(key);
        });
    });
}

function cleanCaptchaStore() {
    const now = Date.now();
    for (const [token, payload] of captchaStore) {
        if (now - payload.createdAt > CAPTCHA_TTL_MS) {
            captchaStore.delete(token);
        }
    }
}

function validateCaptcha(token, answer) {
    cleanCaptchaStore();
    const payload = captchaStore.get(token);
    if (!payload) return false;
    captchaStore.delete(token);
    const numeric = Number(answer);
    return Number.isFinite(numeric) && numeric === payload.answer;
}

function setSessionCookie(res, email, fullName, role) {
    const sid = crypto.randomUUID();
    sessions.set(sid, {
        email,
        fullName,
        role: normalizeRole(role),
        createdAt: Date.now()
    });
    res.cookie(SESSION_COOKIE, sid, {
        httpOnly: true,
        sameSite: 'strict',
        secure: false,
        maxAge: SESSION_TTL_MS
    });
}

function getSessionUser(req) {
    const sid = req.cookies[SESSION_COOKIE];
    if (!sid) return null;
    const session = sessions.get(sid);
    if (!session) return null;
    if (Date.now() - session.createdAt > SESSION_TTL_MS) {
        sessions.delete(sid);
        return null;
    }
    return session;
}

function getGuard(email) {
    const existing = loginGuard.get(email);
    if (!existing) return { attempts: 0, lockedUntil: 0 };
    return existing;
}

function requireAuth(req, res, next) {
    const session = getSessionUser(req);
    if (!session) {
        return res.status(401).json({ error: 'Nao autenticado.' });
    }
    req.sessionUser = session;
    next();
}

function requireAdmin(req, res, next) {
    const session = getSessionUser(req);
    if (!session) {
        return res.status(401).json({ error: 'Nao autenticado.' });
    }
    if (!isAdminRole(session.role)) {
        return res.status(403).json({ error: 'Acesso restrito ao painel administrativo.' });
    }
    req.sessionUser = session;
    next();
}

app.get('/api/auth/captcha', (req, res) => {
    const mode = req.query.mode === 'signup' ? 'signup' : 'login';
    res.json(createCaptcha(mode));
});

app.get('/api/auth/session', (req, res) => {
    const session = getSessionUser(req);
    if (!session) {
        return res.status(401).json({ authenticated: false });
    }
    res.json({
        authenticated: true,
        user: {
            email: session.email,
            fullName: session.fullName,
            role: normalizeRole(session.role)
        }
    });
});

app.post('/api/auth/logout', (req, res) => {
    const sid = req.cookies[SESSION_COOKIE];
    if (sid) {
        sessions.delete(sid);
    }
    res.clearCookie(SESSION_COOKIE);
    res.json({ ok: true });
});

app.post('/api/auth/register', async (req, res) => {
    const {
        fullName,
        email,
        password,
        confirmPassword,
        securityAnswer,
        captchaToken,
        captchaAnswer
    } = req.body || {};

    const cleanName = String(fullName || '').trim();
    const normalizedEmail = normalizeEmail(email);
    const cleanSecurityAnswer = String(securityAnswer || '').trim().toLowerCase();

    if (!cleanName || cleanName.split(/\s+/).length < 2) {
        return res.status(400).json({ error: 'Informe nome completo (nome e sobrenome).' });
    }
    if (!normalizedEmail || !String(password) || !String(confirmPassword) || !cleanSecurityAnswer) {
        return res.status(400).json({ error: 'Preencha todos os campos do cadastro.' });
    }
    if (!validateCaptcha(captchaToken, captchaAnswer)) {
        return res.status(400).json({ error: 'Captcha do cadastro invalido.' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'As senhas nao coincidem.' });
    }
    if (!isStrongPassword(password)) {
        return res.status(400).json({ error: 'Senha fraca: use 8+ chars com maiuscula, minuscula, numero e simbolo.' });
    }

    const users = await readUsers();
    if (users[normalizedEmail]) {
        return res.status(409).json({ error: 'Ja existe conta com esse email.' });
    }

    const initialRole = normalizedEmail === OWNER_EMAIL ? ROLE_OWNER : ROLE_CLIENT;

    const passwordHash = await hashSecret(password);
    const securityHash = await hashSecret(cleanSecurityAnswer);
    users[normalizedEmail] = {
        fullName: cleanName,
        email: normalizedEmail,
        role: initialRole,
        passwordHash,
        securityHash,
        createdAt: Date.now()
    };
    await saveUsers(users);

    setSessionCookie(res, normalizedEmail, cleanName, initialRole);
    res.status(201).json({
        ok: true,
        user: {
            email: normalizedEmail,
            fullName: cleanName,
            role: initialRole
        }
    });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password, captchaToken, captchaAnswer } = req.body || {};
    const normalizedEmail = normalizeEmail(email);

    if (!normalizedEmail || !String(password || '')) {
        return res.status(400).json({ error: 'Informe email e senha para login.' });
    }
    if (!validateCaptcha(captchaToken, captchaAnswer)) {
        return res.status(400).json({ error: 'Captcha do login invalido.' });
    }

    const guard = getGuard(normalizedEmail);
    if (guard.lockedUntil && Date.now() < guard.lockedUntil) {
        const minutes = Math.ceil((guard.lockedUntil - Date.now()) / 60000);
        return res.status(429).json({ error: `Conta temporariamente bloqueada. Tente em ${minutes} min.` });
    }

    const users = await readUsers();
    const user = users[normalizedEmail];
    if (!user) {
        return res.status(404).json({ error: 'Conta nao encontrada.' });
    }

    const passwordOk = await verifySecret(password, user.passwordHash);
    if (!passwordOk) {
        guard.attempts += 1;
        if (guard.attempts >= MAX_LOGIN_ATTEMPTS) {
            guard.lockedUntil = Date.now() + LOGIN_LOCK_MS;
            guard.attempts = 0;
        }
        loginGuard.set(normalizedEmail, guard);
        return res.status(401).json({ error: 'Senha incorreta.' });
    }

    loginGuard.set(normalizedEmail, { attempts: 0, lockedUntil: 0 });
    const role = normalizedEmail === OWNER_EMAIL ? ROLE_OWNER : normalizeRole(user.role);
    setSessionCookie(res, normalizedEmail, user.fullName || normalizedEmail, role);
    res.json({
        ok: true,
        user: {
            email: normalizedEmail,
            fullName: user.fullName || normalizedEmail,
            role
        }
    });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
    const users = await readUsers();
    const list = Object.values(users).map((user) => ({
        fullName: user.fullName || '',
        email: user.email || '',
        role: user.email === OWNER_EMAIL ? ROLE_OWNER : normalizeRole(user.role),
        passwordHash: user.passwordHash || '',
        createdAt: user.createdAt || 0
    }));
    list.sort((a, b) => a.email.localeCompare(b.email));
    res.json({
        currentUser: {
            email: req.sessionUser.email,
            fullName: req.sessionUser.fullName,
            role: normalizeRole(req.sessionUser.role)
        },
        users: list
    });
});

app.patch('/api/admin/users/:email', requireAdmin, async (req, res) => {
    const targetEmail = normalizeEmail(req.params.email);
    const { fullName, role, newPassword } = req.body || {};

    const users = await readUsers();
    const target = users[targetEmail];
    if (!target) {
        return res.status(404).json({ error: 'Usuario nao encontrado.' });
    }

    const actorRole = normalizeRole(req.sessionUser.role);
    const requestedRole = role !== undefined ? normalizeRole(role) : undefined;
    const targetCurrentRole = targetEmail === OWNER_EMAIL ? ROLE_OWNER : normalizeRole(target.role);

    if (targetEmail === OWNER_EMAIL && actorRole !== ROLE_OWNER) {
        return res.status(403).json({ error: 'Somente o Owner pode editar o Owner.' });
    }

    if (requestedRole && requestedRole === ROLE_OWNER && actorRole !== ROLE_OWNER) {
        return res.status(403).json({ error: 'Somente o Owner pode atribuir cargo Owner.' });
    }

    if (actorRole === ROLE_CO_OWNER && targetCurrentRole === ROLE_CO_OWNER && targetEmail !== req.sessionUser.email) {
        return res.status(403).json({ error: 'Co-Owner nao pode editar outro Co-Owner.' });
    }

    if (fullName !== undefined) {
        const cleanName = String(fullName).trim();
        if (!cleanName || cleanName.split(/\s+/).length < 2) {
            return res.status(400).json({ error: 'Nome completo invalido.' });
        }
        target.fullName = cleanName;
    }

    if (requestedRole) {
        target.role = targetEmail === OWNER_EMAIL ? ROLE_OWNER : requestedRole;
    }

    if (newPassword !== undefined && String(newPassword).trim() !== '') {
        if (!isStrongPassword(newPassword)) {
            return res.status(400).json({ error: 'Nova senha fraca.' });
        }
        target.passwordHash = await hashSecret(newPassword);
    }

    users[targetEmail] = target;
    await saveUsers(users);

    // Atualiza sessoes ativas do usuario alterado
    for (const session of sessions.values()) {
        if (session.email === targetEmail) {
            session.fullName = target.fullName || session.fullName;
            session.role = targetEmail === OWNER_EMAIL ? ROLE_OWNER : normalizeRole(target.role);
        }
    }

    res.json({ ok: true });
});

app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

ensureUsersFile()
    .then(() => {
        app.listen(PORT, () => {
            console.log(`DarkByte API running at http://localhost:${PORT}`);
        });
    })
    .catch((error) => {
        console.error('Failed to initialize backend', error);
        process.exit(1);
    });
