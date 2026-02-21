const express = require('express');
const initSqlJs = require('sql.js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'lottery.db');
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-change-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

let db = null;

// ==================== SECURITY MIDDLEWARE ====================
// Helmet for HTTP headers security
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
        /\.netlify\.app$/  // Allow all Netlify subdomains
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: { success: false, message: 'Too many requests, please try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per windowMs
    message: { success: false, message: 'Too many login attempts, please try again later.' }
});

app.use('/api/', limiter);
app.use('/api/login', loginLimiter);

app.use(express.json({ limit: '10kb' })); // Limit body size

// ==================== JWT MIDDLEWARE ====================
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

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

    // Setup default admin with hashed password
    const userCount = db.exec('SELECT COUNT(*) as cnt FROM users')[0]?.values[0][0] || 0;
    if (userCount === 0) {
        const hashedPassword = await bcrypt.hash('admin123', 10);
        db.run('INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)', ['admin', hashedPassword, new Date().toISOString()]);
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

// ==================== AUTH API ====================
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password required' });
    }
    
    const result = db.exec('SELECT * FROM users WHERE username = ?', [username]);
    if (result.length > 0 && result[0].values.length > 0) {
        const storedPassword = result[0].values[0][1];
        
        // Check if password is hashed (bcrypt hashes start with $2)
        let isValid = false;
        if (storedPassword.startsWith('$2')) {
            isValid = await bcrypt.compare(password, storedPassword);
        } else {
            // Legacy plain text password - migrate to hashed
            isValid = (password === storedPassword);
            if (isValid) {
                const hashedPassword = await bcrypt.hash(password, 10);
                db.run('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, username]);
                saveDB();
            }
        }
        
        if (isValid) {
            const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ success: true, token, user: { username } });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } else {
        res.json({ success: false, message: 'Invalid credentials' });
    }
});

app.get('/api/verify', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// ==================== PROTECTED ROUTES ====================
app.get('/api/users', authenticateToken, (req, res) => {
    const result = db.exec('SELECT username, created_at FROM users ORDER BY created_at');
    const users = result.length > 0 ? result[0].values.map(row => ({ username: row[0], createdAt: row[1] })) : [];
    res.json(users);
});

app.post('/api/users', authenticateToken, async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password required' });
    }
    
    if (password.length < 6) {
        return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)', [username, hashedPassword, new Date().toISOString()]);
        saveDB();
        res.json({ success: true });
    } catch (e) {
        res.json({ success: false, message: 'User already exists' });
    }
});

app.put('/api/users/:username', authenticateToken, async (req, res) => {
    const { password } = req.body;
    
    if (!password || password.length < 6) {
        return res.json({ success: false, message: 'Password must be at least 6 characters' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, req.params.username]);
    saveDB();
    res.json({ success: true });
});

app.delete('/api/users/:username', authenticateToken, (req, res) => {
    if (req.params.username === 'admin') {
        return res.json({ success: false, message: 'Cannot delete admin user' });
    }
    db.run('DELETE FROM users WHERE username = ?', [req.params.username]);
    saveDB();
    res.json({ success: true });
});

// ==================== SETTINGS API ====================
app.get('/api/settings', authenticateToken, (req, res) => {
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

app.put('/api/settings', authenticateToken, (req, res) => {
    const { alertThreshold, defaultLimit2Digit, defaultLimit3DigitTode, defaultLimit3DigitTeng } = req.body;
    db.run(
        'UPDATE settings SET alert_threshold = ?, default_limit_2digit = ?, default_limit_3digit_tode = ?, default_limit_3digit_teng = ? WHERE key = ?',
        [alertThreshold, defaultLimit2Digit, defaultLimit3DigitTode, defaultLimit3DigitTeng, 'main']
    );
    saveDB();
    res.json({ success: true });
});

// ==================== 2-DIGIT API ====================
app.get('/api/limits/2digit', authenticateToken, (req, res) => {
    const result = db.exec('SELECT number, limit_amount, amount FROM limits_2digit ORDER BY number');
    const limits = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            limits[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(limits);
});

app.put('/api/limits/2digit/:number', authenticateToken, (req, res) => {
    const { limit, amount } = req.body;
    const number = req.params.number.padStart(2, '0');
    
    const existing = db.exec('SELECT * FROM limits_2digit WHERE number = ?', [number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        if (limit !== undefined) {
            db.run('UPDATE limits_2digit SET limit_amount = ? WHERE number = ?', [limit, number]);
        }
        if (amount !== undefined) {
            db.run('UPDATE limits_2digit SET amount = ? WHERE number = ?', [amount, number]);
        }
    } else {
        db.run('INSERT INTO limits_2digit (number, limit_amount, amount) VALUES (?, ?, ?)', [number, limit || 5000, amount || 0]);
    }
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/2digit/:number/add', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const number = req.params.number.padStart(2, '0');
    
    db.run('UPDATE limits_2digit SET amount = amount + ? WHERE number = ?', [amount, number]);
    saveDB();
    
    const result = db.exec('SELECT amount, limit_amount FROM limits_2digit WHERE number = ?', [number]);
    const newAmount = result[0]?.values[0]?.[0] || 0;
    const limitAmount = result[0]?.values[0]?.[1] || 5000;
    
    res.json({ success: true, newAmount, limit: limitAmount });
});

app.put('/api/limits/2digit/all', authenticateToken, (req, res) => {
    const { limit } = req.body;
    db.run('UPDATE limits_2digit SET limit_amount = ?', [limit]);
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/2digit/reset', authenticateToken, (req, res) => {
    db.run('UPDATE limits_2digit SET amount = 0');
    saveDB();
    res.json({ success: true });
});

// ==================== 3-DIGIT TODE API ====================
app.get('/api/limits/3digit/tode', authenticateToken, (req, res) => {
    const result = db.exec('SELECT number, limit_amount, amount FROM limits_3digit_tode ORDER BY number');
    const limits = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            limits[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(limits);
});

app.put('/api/limits/3digit/tode/:number', authenticateToken, (req, res) => {
    const { limit, amount } = req.body;
    const number = req.params.number.padStart(3, '0');
    
    const existing = db.exec('SELECT * FROM limits_3digit_tode WHERE number = ?', [number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        if (limit !== undefined) {
            db.run('UPDATE limits_3digit_tode SET limit_amount = ? WHERE number = ?', [limit, number]);
        }
        if (amount !== undefined) {
            db.run('UPDATE limits_3digit_tode SET amount = ? WHERE number = ?', [amount, number]);
        }
    } else {
        db.run('INSERT INTO limits_3digit_tode (number, limit_amount, amount) VALUES (?, ?, ?)', [number, limit || 3000, amount || 0]);
    }
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/3digit/tode/:number/add', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const number = req.params.number.padStart(3, '0');
    
    const existing = db.exec('SELECT * FROM limits_3digit_tode WHERE number = ?', [number]);
    if (existing.length === 0 || existing[0].values.length === 0) {
        const settings = db.exec('SELECT default_limit_3digit_tode FROM settings WHERE key = ?', ['main']);
        const defaultLimit = settings[0]?.values[0]?.[0] || 3000;
        db.run('INSERT INTO limits_3digit_tode (number, limit_amount, amount) VALUES (?, ?, ?)', [number, defaultLimit, amount]);
    } else {
        db.run('UPDATE limits_3digit_tode SET amount = amount + ? WHERE number = ?', [amount, number]);
    }
    saveDB();
    
    const result = db.exec('SELECT amount, limit_amount FROM limits_3digit_tode WHERE number = ?', [number]);
    const newAmount = result[0]?.values[0]?.[0] || 0;
    const limitAmount = result[0]?.values[0]?.[1] || 3000;
    
    res.json({ success: true, newAmount, limit: limitAmount });
});

app.delete('/api/limits/3digit/tode/:number', authenticateToken, (req, res) => {
    const number = req.params.number.padStart(3, '0');
    db.run('DELETE FROM limits_3digit_tode WHERE number = ?', [number]);
    saveDB();
    res.json({ success: true });
});

app.put('/api/limits/3digit/tode/all', authenticateToken, (req, res) => {
    const { limit } = req.body;
    db.run('UPDATE limits_3digit_tode SET limit_amount = ?', [limit]);
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/3digit/tode/reset', authenticateToken, (req, res) => {
    db.run('DELETE FROM limits_3digit_tode');
    saveDB();
    res.json({ success: true });
});

// ==================== 3-DIGIT TENG API ====================
app.get('/api/limits/3digit/teng', authenticateToken, (req, res) => {
    const result = db.exec('SELECT number, limit_amount, amount FROM limits_3digit_teng ORDER BY number');
    const limits = {};
    if (result.length > 0) {
        result[0].values.forEach(row => {
            limits[row[0]] = { limit: row[1], amount: row[2] };
        });
    }
    res.json(limits);
});

app.put('/api/limits/3digit/teng/:number', authenticateToken, (req, res) => {
    const { limit, amount } = req.body;
    const number = req.params.number.padStart(3, '0');
    
    const existing = db.exec('SELECT * FROM limits_3digit_teng WHERE number = ?', [number]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        if (limit !== undefined) {
            db.run('UPDATE limits_3digit_teng SET limit_amount = ? WHERE number = ?', [limit, number]);
        }
        if (amount !== undefined) {
            db.run('UPDATE limits_3digit_teng SET amount = ? WHERE number = ?', [amount, number]);
        }
    } else {
        db.run('INSERT INTO limits_3digit_teng (number, limit_amount, amount) VALUES (?, ?, ?)', [number, limit || 2000, amount || 0]);
    }
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/3digit/teng/:number/add', authenticateToken, (req, res) => {
    const { amount } = req.body;
    const number = req.params.number.padStart(3, '0');
    
    const existing = db.exec('SELECT * FROM limits_3digit_teng WHERE number = ?', [number]);
    if (existing.length === 0 || existing[0].values.length === 0) {
        const settings = db.exec('SELECT default_limit_3digit_teng FROM settings WHERE key = ?', ['main']);
        const defaultLimit = settings[0]?.values[0]?.[0] || 2000;
        db.run('INSERT INTO limits_3digit_teng (number, limit_amount, amount) VALUES (?, ?, ?)', [number, defaultLimit, amount]);
    } else {
        db.run('UPDATE limits_3digit_teng SET amount = amount + ? WHERE number = ?', [amount, number]);
    }
    saveDB();
    
    const result = db.exec('SELECT amount, limit_amount FROM limits_3digit_teng WHERE number = ?', [number]);
    const newAmount = result[0]?.values[0]?.[0] || 0;
    const limitAmount = result[0]?.values[0]?.[1] || 2000;
    
    res.json({ success: true, newAmount, limit: limitAmount });
});

app.delete('/api/limits/3digit/teng/:number', authenticateToken, (req, res) => {
    const number = req.params.number.padStart(3, '0');
    db.run('DELETE FROM limits_3digit_teng WHERE number = ?', [number]);
    saveDB();
    res.json({ success: true });
});

app.put('/api/limits/3digit/teng/all', authenticateToken, (req, res) => {
    const { limit } = req.body;
    db.run('UPDATE limits_3digit_teng SET limit_amount = ?', [limit]);
    saveDB();
    res.json({ success: true });
});

app.post('/api/limits/3digit/teng/reset', authenticateToken, (req, res) => {
    db.run('DELETE FROM limits_3digit_teng');
    saveDB();
    res.json({ success: true });
});

// ==================== DASHBOARD API ====================
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
    const settings = db.exec('SELECT alert_threshold FROM settings WHERE key = ?', ['main']);
    const threshold = settings[0]?.values[0]?.[0] || 80;
    
    // 2-digit stats
    const stats2d = db.exec('SELECT COUNT(*) FROM limits_2digit WHERE amount > 0');
    const total2d = stats2d[0]?.values[0]?.[0] || 0;
    
    // 3-digit tode stats
    const stats3dTode = db.exec('SELECT COUNT(*) FROM limits_3digit_tode WHERE amount > 0');
    const total3dTode = stats3dTode[0]?.values[0]?.[0] || 0;
    
    // 3-digit teng stats
    const stats3dTeng = db.exec('SELECT COUNT(*) FROM limits_3digit_teng WHERE amount > 0');
    const total3dTeng = stats3dTeng[0]?.values[0]?.[0] || 0;
    
    // Near limit count
    const nearLimit2d = db.exec(`SELECT COUNT(*) FROM limits_2digit WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}`);
    const nearLimit3dTode = db.exec(`SELECT COUNT(*) FROM limits_3digit_tode WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}`);
    const nearLimit3dTeng = db.exec(`SELECT COUNT(*) FROM limits_3digit_teng WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}`);
    
    const nearLimitCount = (nearLimit2d[0]?.values[0]?.[0] || 0) + 
                          (nearLimit3dTode[0]?.values[0]?.[0] || 0) + 
                          (nearLimit3dTeng[0]?.values[0]?.[0] || 0);
    
    res.json({
        total2Digit: total2d,
        total3DigitTode: total3dTode,
        total3DigitTeng: total3dTeng,
        nearLimitCount
    });
});

app.get('/api/dashboard/alerts', authenticateToken, (req, res) => {
    const settings = db.exec('SELECT alert_threshold FROM settings WHERE key = ?', ['main']);
    const threshold = settings[0]?.values[0]?.[0] || 80;
    
    const alerts = [];
    
    // 2-digit alerts
    const alerts2d = db.exec(`
        SELECT number, amount, limit_amount, (amount * 100.0 / limit_amount) as percent 
        FROM limits_2digit 
        WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}
        ORDER BY percent DESC
    `);
    
    if (alerts2d.length > 0) {
        alerts2d[0].values.forEach(row => {
            alerts.push({
                type: '2 ตัว',
                number: row[0],
                amount: row[1],
                limit: row[2],
                percent: row[3]
            });
        });
    }
    
    // 3-digit tode alerts
    const alerts3dTode = db.exec(`
        SELECT number, amount, limit_amount, (amount * 100.0 / limit_amount) as percent 
        FROM limits_3digit_tode 
        WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}
        ORDER BY percent DESC
    `);
    
    if (alerts3dTode.length > 0) {
        alerts3dTode[0].values.forEach(row => {
            alerts.push({
                type: '3 ตัวโต๊ด',
                number: row[0],
                amount: row[1],
                limit: row[2],
                percent: row[3]
            });
        });
    }
    
    // 3-digit teng alerts
    const alerts3dTeng = db.exec(`
        SELECT number, amount, limit_amount, (amount * 100.0 / limit_amount) as percent 
        FROM limits_3digit_teng 
        WHERE limit_amount > 0 AND (amount * 100.0 / limit_amount) >= ${threshold}
        ORDER BY percent DESC
    `);
    
    if (alerts3dTeng.length > 0) {
        alerts3dTeng[0].values.forEach(row => {
            alerts.push({
                type: '3 ตัวเต็ง',
                number: row[0],
                amount: row[1],
                limit: row[2],
                percent: row[3]
            });
        });
    }
    
    // Sort all alerts by percent descending
    alerts.sort((a, b) => b.percent - a.percent);
    
    res.json(alerts);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== START SERVER ====================
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});
