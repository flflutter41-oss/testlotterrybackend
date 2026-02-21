const express = require('express');
const initSqlJs = require('sql.js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'lottery.db');
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

let db = null;

// ==================== SECURITY MIDDLEWARE ====================
app.use(helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: false
}));

// CORS configuration
const corsOptions = {
    origin: [
        FRONTEND_URL,
        'http://localhost:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'https://lottery-limit.netlify.app',
        /\.netlify\.app$/
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { success: false, message: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { success: false, message: 'Too many login attempts, please try again later.' }
});

app.use('/api/', limiter);
app.use('/api/login', loginLimiter);

app.use(express.json({ limit: '10kb' }));

// ==================== DATABASE FUNCTIONS ====================
function saveDB() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_FILE, buffer);
    }
}

async function initDatabase() {
    const SQL = await initSqlJs();
    
    if (fs.existsSync(DB_FILE)) {
        const fileBuffer = fs.readFileSync(DB_FILE);
        db = new SQL.Database(fileBuffer);
        console.log('Loaded existing database');
    } else {
        db = new SQL.Database();
        console.log('Created new database');
    }
    
    // Create tables
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            alert_threshold INTEGER DEFAULT 80,
            default_limit_2digit INTEGER DEFAULT 5000,
            default_limit_3digit_tode INTEGER DEFAULT 3000,
            default_limit_3digit_teng INTEGER DEFAULT 2000
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS limits_2digit (
            number TEXT PRIMARY KEY,
            limit_amount INTEGER DEFAULT 5000,
            amount INTEGER DEFAULT 0
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS limits_3digit_tode (
            number TEXT PRIMARY KEY,
            limit_amount INTEGER DEFAULT 3000,
            amount INTEGER DEFAULT 0
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS limits_3digit_teng (
            number TEXT PRIMARY KEY,
            limit_amount INTEGER DEFAULT 2000,
            amount INTEGER DEFAULT 0
        )
    `);
    
    db.run(`
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            type TEXT NOT NULL,
            number TEXT NOT NULL,
            amount REAL NOT NULL,
            total_amount REAL NOT NULL,
            limit_amount REAL NOT NULL
        )
    `);

    // Setup default data
    const userCount = db.exec('SELECT COUNT(*) as cnt FROM users')[0]?.values[0][0] || 0;
    if (userCount === 0) {
        db.run('INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)', ['admin', 'admin123', new Date().toISOString()]);
    }

    const settingsCount = db.exec('SELECT COUNT(*) as cnt FROM settings')[0]?.values[0][0] || 0;
    if (settingsCount === 0) {
        db.run('INSERT INTO settings (key, alert_threshold, default_limit_2digit, default_limit_3digit_tode, default_limit_3digit_teng) VALUES (?, ?, ?, ?, ?)', ['main', 80, 5000, 3000, 2000]);
    }

    const limit2Count = db.exec('SELECT COUNT(*) as cnt FROM limits_2digit')[0]?.values[0][0] || 0;
    if (limit2Count === 0) {
        for (let i = 0; i <= 99; i++) {
            const num = i.toString().padStart(2, '0');
            db.run('INSERT INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [num, 5000, 0]);
        }
    }

    saveDB();
    console.log('Database initialized');
}

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ==================== AUTH API ====================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const result = db.exec('SELECT * FROM users WHERE username = ? AND password = ?', [username, password]);
    if (result.length > 0 && result[0].values.length > 0) {
        res.json({ success: true, user: { username: result[0].values[0][0] } });
    } else {
        res.json({ success: false, message: 'Invalid credentials' });
    }
});

app.get('/api/users', (req, res) => {
    const result = db.exec('SELECT username, created_at FROM users ORDER BY created_at');
    const users = result.length > 0 ? result[0].values.map(row => ({ username: row[0], createdAt: row[1] })) : [];
    res.json(users);
});

app.post('/api/users', (req, res) => {
    const { username, password } = req.body;
    try {
        db.run('INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)', [username, password, new Date().toISOString()]);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: 'User already exists' });
    }
});

app.put('/api/users/:username', (req, res) => {
    const { password } = req.body;
    db.run('UPDATE users SET password = ? WHERE username = ?', [password, req.params.username]);
    saveDB();
    res.json({ success: true });
});

app.delete('/api/users/:username', (req, res) => {
    db.run('DELETE FROM users WHERE username = ?', [req.params.username]);
    saveDB();
    res.json({ success: true });
});

// ==================== SETTINGS API ====================
app.get('/api/settings', (req, res) => {
    const result = db.exec('SELECT * FROM settings WHERE key = ?', ['main']);
    if (result.length > 0 && result[0].values.length > 0) {
        const row = result[0].values[0];
        res.json({
            alertThreshold: row[1],
            defaultLimit2Digit: row[2],
            defaultLimit3DigitTode: row[3],
            defaultLimit3DigitTeng: row[4]
        });
    } else {
        res.json({
            alertThreshold: 80,
            defaultLimit2Digit: 5000,
            defaultLimit3DigitTode: 3000,
            defaultLimit3DigitTeng: 2000
        });
    }
});

app.put('/api/settings', (req, res) => {
    const { alertThreshold, defaultLimit2Digit, defaultLimit3DigitTode, defaultLimit3DigitTeng } = req.body;
    db.run('UPDATE settings SET alert_threshold = ?, default_limit_2digit = ?, default_limit_3digit_tode = ?, default_limit_3digit_teng = ? WHERE key = ?', 
        [alertThreshold, defaultLimit2Digit, defaultLimit3DigitTode, defaultLimit3DigitTeng, 'main']);
    saveDB();
    res.json({ success: true });
});

// ==================== 2-DIGIT API ====================
app.get('/api/limits/2digit', (req, res) => {
    const result = db.exec('SELECT * FROM limits_2digit ORDER BY number');
    const data = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            data[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(data);
});

app.put('/api/limits/2digit/:number', (req, res) => {
    const { limit, amount } = req.body;
    const existing = db.exec('SELECT * FROM limits_2digit WHERE number = ?', [req.params.number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        db.run('UPDATE limits_2digit SET limit_amount = ?, amount = ? WHERE number = ?', [limit, amount, req.params.number]);
    } else {
        db.run('INSERT INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [req.params.number, limit, amount]);
    }
    saveDB();
    res.json({ success: true });
});

app.put('/api/limits/2digit', (req, res) => {
    const data = req.body;
    for (const [number, info] of Object.entries(data)) {
        db.run('INSERT OR REPLACE INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [number, info.limit, info.amount]);
    }
    saveDB();
    res.json({ success: true });
});

// ==================== 3-DIGIT TODE API ====================
app.get('/api/limits/3digit-tode', (req, res) => {
    const result = db.exec('SELECT * FROM limits_3digit_tode ORDER BY number');
    const data = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            data[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(data);
});

app.put('/api/limits/3digit-tode/:number', (req, res) => {
    const { limit, amount } = req.body;
    const existing = db.exec('SELECT * FROM limits_3digit_tode WHERE number = ?', [req.params.number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        db.run('UPDATE limits_3digit_tode SET limit_amount = ?, amount = ? WHERE number = ?', [limit, amount, req.params.number]);
    } else {
        db.run('INSERT INTO limits_3digit_tode (number, limit_amount, amount) VALUES (?, ?, ?)', [req.params.number, limit, amount]);
    }
    saveDB();
    res.json({ success: true });
});

app.delete('/api/limits/3digit-tode/:number', (req, res) => {
    db.run('DELETE FROM limits_3digit_tode WHERE number = ?', [req.params.number]);
    saveDB();
    res.json({ success: true });
});

app.put('/api/limits/3digit-tode', (req, res) => {
    const data = req.body;
    for (const [number, info] of Object.entries(data)) {
        db.run('INSERT OR REPLACE INTO limits_3digit_tode (number, limit_amount, amount) VALUES (?, ?, ?)', [number, info.limit, info.amount]);
    }
    saveDB();
    res.json({ success: true });
});

// ==================== 3-DIGIT TENG API ====================
app.get('/api/limits/3digit-teng', (req, res) => {
    const result = db.exec('SELECT * FROM limits_3digit_teng ORDER BY number');
    const data = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            data[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(data);
});

app.put('/api/limits/3digit-teng/:number', (req, res) => {
    const { limit, amount } = req.body;
    const existing = db.exec('SELECT * FROM limits_3digit_teng WHERE number = ?', [req.params.number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        db.run('UPDATE limits_3digit_teng SET limit_amount = ?, amount = ? WHERE number = ?', [limit, amount, req.params.number]);
    } else {
        db.run('INSERT INTO limits_3digit_teng (number, limit_amount, amount) VALUES (?, ?, ?)', [req.params.number, limit, amount]);
    }
    saveDB();
    res.json({ success: true });
});

app.delete('/api/limits/3digit-teng/:number', (req, res) => {
    db.run('DELETE FROM limits_3digit_teng WHERE number = ?', [req.params.number]);
    saveDB();
    res.json({ success: true });
});

app.put('/api/limits/3digit-teng', (req, res) => {
    const data = req.body;
    for (const [number, info] of Object.entries(data)) {
        db.run('INSERT OR REPLACE INTO limits_3digit_teng (number, limit_amount, amount) VALUES (?, ?, ?)', [number, info.limit, info.amount]);
    }
    saveDB();
    res.json({ success: true });
});

// ==================== TRANSACTIONS API ====================
app.get('/api/transactions', (req, res) => {
    const result = db.exec('SELECT * FROM transactions ORDER BY date DESC');
    const transactions = result.length > 0 ? result[0].values.map(row => ({
        id: row[0],
        date: row[1],
        type: row[2],
        number: row[3],
        amount: row[4],
        totalAmount: row[5],
        limit: row[6]
    })) : [];
    res.json(transactions);
});

app.post('/api/transactions', (req, res) => {
    const { date, type, number, amount, totalAmount, limit } = req.body;
    db.run('INSERT INTO transactions (date, type, number, amount, total_amount, limit_amount) VALUES (?, ?, ?, ?, ?, ?)', 
        [date, type, number, amount, totalAmount, limit]);
    saveDB();
    const lastId = db.exec('SELECT last_insert_rowid()')[0].values[0][0];
    res.json({ success: true, id: lastId });
});

app.delete('/api/transactions/:id', (req, res) => {
    db.run('DELETE FROM transactions WHERE id = ?', [req.params.id]);
    saveDB();
    res.json({ success: true });
});

app.delete('/api/transactions', (req, res) => {
    db.run('DELETE FROM transactions');
    saveDB();
    res.json({ success: true });
});

// ==================== EXPORT/IMPORT API ====================
app.get('/api/export', (req, res) => {
    const usersResult = db.exec('SELECT * FROM users');
    const users = usersResult.length > 0 ? usersResult[0].values.map(r => ({ username: r[0], password: r[1], createdAt: r[2] })) : [];
    
    const settingsResult = db.exec('SELECT * FROM settings WHERE key = ?', ['main']);
    const settings = settingsResult.length > 0 ? {
        alertThreshold: settingsResult[0].values[0][1],
        defaultLimit2Digit: settingsResult[0].values[0][2],
        defaultLimit3DigitTode: settingsResult[0].values[0][3],
        defaultLimit3DigitTeng: settingsResult[0].values[0][4]
    } : {};
    
    const limits2Result = db.exec('SELECT * FROM limits_2digit');
    const limits2digit = limits2Result.length > 0 ? limits2Result[0].values.map(r => ({ number: r[0], limit: r[1], amount: r[2] })) : [];
    
    const limits3TodeResult = db.exec('SELECT * FROM limits_3digit_tode');
    const limits3digitTode = limits3TodeResult.length > 0 ? limits3TodeResult[0].values.map(r => ({ number: r[0], limit: r[1], amount: r[2] })) : [];
    
    const limits3TengResult = db.exec('SELECT * FROM limits_3digit_teng');
    const limits3digitTeng = limits3TengResult.length > 0 ? limits3TengResult[0].values.map(r => ({ number: r[0], limit: r[1], amount: r[2] })) : [];
    
    const transResult = db.exec('SELECT * FROM transactions');
    const transactions = transResult.length > 0 ? transResult[0].values.map(r => ({ 
        id: r[0], date: r[1], type: r[2], number: r[3], amount: r[4], totalAmount: r[5], limit: r[6] 
    })) : [];
    
    res.json({
        users,
        settings,
        limits2digit,
        limits3digitTode,
        limits3digitTeng,
        transactions,
        exportDate: new Date().toISOString()
    });
});

app.post('/api/import', (req, res) => {
    const data = req.body;
    try {
        if (data.users) {
            db.run('DELETE FROM users');
            data.users.forEach(u => {
                db.run('INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)', [u.username, u.password, u.createdAt || new Date().toISOString()]);
            });
        }
        
        if (data.settings) {
            db.run('UPDATE settings SET alert_threshold = ?, default_limit_2digit = ?, default_limit_3digit_tode = ?, default_limit_3digit_teng = ? WHERE key = ?',
                [data.settings.alertThreshold, data.settings.defaultLimit2Digit, data.settings.defaultLimit3DigitTode, data.settings.defaultLimit3DigitTeng, 'main']);
        }
        
        if (data.limits2digit) {
            db.run('DELETE FROM limits_2digit');
            data.limits2digit.forEach(i => {
                db.run('INSERT INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [i.number, i.limit, i.amount]);
            });
        }
        
        if (data.limits3digitTode) {
            db.run('DELETE FROM limits_3digit_tode');
            data.limits3digitTode.forEach(i => {
                db.run('INSERT INTO limits_3digit_tode (number, limit_amount, amount) VALUES (?, ?, ?)', [i.number, i.limit, i.amount]);
            });
        }
        
        if (data.limits3digitTeng) {
            db.run('DELETE FROM limits_3digit_teng');
            data.limits3digitTeng.forEach(i => {
                db.run('INSERT INTO limits_3digit_teng (number, limit_amount, amount) VALUES (?, ?, ?)', [i.number, i.limit, i.amount]);
            });
        }
        
        if (data.transactions) {
            db.run('DELETE FROM transactions');
            data.transactions.forEach(t => {
                db.run('INSERT INTO transactions (date, type, number, amount, total_amount, limit_amount) VALUES (?, ?, ?, ?, ?, ?)',
                    [t.date, t.type, t.number, t.amount, t.totalAmount, t.limit]);
            });
        }
        
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: e.message });
    }
});

app.post('/api/clear-amounts', (req, res) => {
    db.run('UPDATE limits_2digit SET amount = 0');
    db.run('UPDATE limits_3digit_tode SET amount = 0');
    db.run('UPDATE limits_3digit_teng SET amount = 0');
    saveDB();
    res.json({ success: true });
});

app.post('/api/clear-all', (req, res) => {
    db.run('DELETE FROM limits_2digit');
    db.run('DELETE FROM limits_3digit_tode');
    db.run('DELETE FROM limits_3digit_teng');
    db.run('DELETE FROM transactions');
    for (let i = 0; i <= 99; i++) {
        const num = i.toString().padStart(2, '0');
        db.run('INSERT INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [num, 5000, 0]);
    }
    saveDB();
    res.json({ success: true });
});

// ==================== DATABASE INFO ====================
app.get('/api/db-info', (req, res) => {
    const info = {
        type: 'SQLite (sql.js on Node.js)',
        file: 'lottery.db',
        tables: {}
    };
    info.tables.users = db.exec('SELECT COUNT(*) FROM users')[0]?.values[0][0] || 0;
    info.tables.limits_2digit = db.exec('SELECT COUNT(*) FROM limits_2digit')[0]?.values[0][0] || 0;
    info.tables.limits_3digit_tode = db.exec('SELECT COUNT(*) FROM limits_3digit_tode')[0]?.values[0][0] || 0;
    info.tables.limits_3digit_teng = db.exec('SELECT COUNT(*) FROM limits_3digit_teng')[0]?.values[0][0] || 0;
    info.tables.transactions = db.exec('SELECT COUNT(*) FROM transactions')[0]?.values[0][0] || 0;
    res.json(info);
});

// Start Server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${FRONTEND_URL}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
