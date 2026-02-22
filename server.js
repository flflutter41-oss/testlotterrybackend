const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/lottery';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Trust proxy for Render (reverse proxy)
app.set('trust proxy', 1);

// ==================== MONGODB SCHEMAS ====================
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});

const settingsSchema = new mongoose.Schema({
    key: { type: String, default: 'main', unique: true },
    alertThreshold: { type: Number, default: 80 },
    defaultLimit2Digit: { type: Number, default: 5000 },
    defaultLimit3DigitTode: { type: Number, default: 3000 },
    defaultLimit3DigitTeng: { type: Number, default: 2000 }
});

const limit2DigitSchema = new mongoose.Schema({
    number: { type: String, required: true, unique: true },
    limit: { type: Number, default: 5000 },
    amount: { type: Number, default: 0 }
});

const limit3DigitTodeSchema = new mongoose.Schema({
    number: { type: String, required: true, unique: true },
    limit: { type: Number, default: 3000 },
    amount: { type: Number, default: 0 }
});

const limit3DigitTengSchema = new mongoose.Schema({
    number: { type: String, required: true, unique: true },
    limit: { type: Number, default: 2000 },
    amount: { type: Number, default: 0 }
});

const transactionSchema = new mongoose.Schema({
    date: { type: String, required: true },
    type: { type: String, required: true },
    number: { type: String, required: true },
    amount: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    limit: { type: Number, required: true }
});

const User = mongoose.model('User', userSchema);
const Settings = mongoose.model('Settings', settingsSchema);
const Limit2Digit = mongoose.model('Limit2Digit', limit2DigitSchema);
const Limit3DigitTode = mongoose.model('Limit3DigitTode', limit3DigitTodeSchema);
const Limit3DigitTeng = mongoose.model('Limit3DigitTeng', limit3DigitTengSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

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

// ==================== DATABASE INITIALIZATION ====================
async function initDatabase() {
    try {
        await mongoose.connect(MONGODB_URI);
        console.log('Connected to MongoDB');

        // Create default admin user if not exists
        const userCount = await User.countDocuments();
        if (userCount === 0) {
            await User.create({ username: 'admin', password: 'admin123' });
            console.log('Created default admin user');
        }

        // Create default settings if not exists
        const settingsCount = await Settings.countDocuments();
        if (settingsCount === 0) {
            await Settings.create({ key: 'main' });
            console.log('Created default settings');
        }

        // Create default 2-digit limits if not exists
        const limit2Count = await Limit2Digit.countDocuments();
        if (limit2Count === 0) {
            const limits = [];
            for (let i = 0; i <= 99; i++) {
                const num = i.toString().padStart(2, '0');
                limits.push({ number: num, limit: 5000, amount: 0 });
            }
            await Limit2Digit.insertMany(limits);
            console.log('Created default 2-digit limits');
        }

        console.log('Database initialized');
    } catch (err) {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    }
}

// ==================== HEALTH CHECK ====================
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString(), db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// ==================== AUTH API ====================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username, password });
        if (user) {
            res.json({ success: true, user: { username: user.username } });
        } else {
            res.json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.get('/api/users', async (req, res) => {
    try {
        const users = await User.find().select('username createdAt').sort('createdAt');
        res.json(users.map(u => ({ username: u.username, createdAt: u.createdAt })));
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/users', async (req, res) => {
    try {
        const { username, password } = req.body;
        await User.create({ username, password });
        res.json({ success: true });
    } catch (err) {
        res.json({ success: false, message: 'User already exists' });
    }
});

app.put('/api/users/:username', async (req, res) => {
    try {
        const { password } = req.body;
        await User.updateOne({ username: req.params.username }, { password });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/users/:username', async (req, res) => {
    try {
        await User.deleteOne({ username: req.params.username });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== SETTINGS API ====================
app.get('/api/settings', async (req, res) => {
    try {
        const settings = await Settings.findOne({ key: 'main' });
        if (settings) {
            res.json({
                alertThreshold: settings.alertThreshold,
                defaultLimit2Digit: settings.defaultLimit2Digit,
                defaultLimit3DigitTode: settings.defaultLimit3DigitTode,
                defaultLimit3DigitTeng: settings.defaultLimit3DigitTeng
            });
        } else {
            res.json({
                alertThreshold: 80,
                defaultLimit2Digit: 5000,
                defaultLimit3DigitTode: 3000,
                defaultLimit3DigitTeng: 2000
            });
        }
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/settings', async (req, res) => {
    try {
        const { alertThreshold, defaultLimit2Digit, defaultLimit3DigitTode, defaultLimit3DigitTeng } = req.body;
        await Settings.updateOne({ key: 'main' }, {
            alertThreshold,
            defaultLimit2Digit,
            defaultLimit3DigitTode,
            defaultLimit3DigitTeng
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== 2-DIGIT API ====================
app.get('/api/limits/2digit', async (req, res) => {
    try {
        const limits = await Limit2Digit.find().sort('number');
        const data = {};
        limits.forEach(l => {
            data[l.number] = { limit: l.limit, amount: l.amount };
        });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/2digit/:number', async (req, res) => {
    try {
        const { limit, amount } = req.body;
        await Limit2Digit.updateOne(
            { number: req.params.number },
            { limit, amount },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/2digit', async (req, res) => {
    try {
        const data = req.body;
        const bulkOps = Object.entries(data).map(([number, info]) => ({
            updateOne: {
                filter: { number },
                update: { limit: info.limit, amount: info.amount },
                upsert: true
            }
        }));
        await Limit2Digit.bulkWrite(bulkOps);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== 3-DIGIT TODE API ====================
app.get('/api/limits/3digit-tode', async (req, res) => {
    try {
        const limits = await Limit3DigitTode.find().sort('number');
        const data = {};
        limits.forEach(l => {
            data[l.number] = { limit: l.limit, amount: l.amount };
        });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/3digit-tode/:number', async (req, res) => {
    try {
        const { limit, amount } = req.body;
        await Limit3DigitTode.updateOne(
            { number: req.params.number },
            { limit, amount },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/limits/3digit-tode/:number', async (req, res) => {
    try {
        await Limit3DigitTode.deleteOne({ number: req.params.number });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/3digit-tode', async (req, res) => {
    try {
        const data = req.body;
        const bulkOps = Object.entries(data).map(([number, info]) => ({
            updateOne: {
                filter: { number },
                update: { limit: info.limit, amount: info.amount },
                upsert: true
            }
        }));
        await Limit3DigitTode.bulkWrite(bulkOps);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== 3-DIGIT TENG API ====================
app.get('/api/limits/3digit-teng', async (req, res) => {
    try {
        const limits = await Limit3DigitTeng.find().sort('number');
        const data = {};
        limits.forEach(l => {
            data[l.number] = { limit: l.limit, amount: l.amount };
        });
        res.json(data);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/3digit-teng/:number', async (req, res) => {
    try {
        const { limit, amount } = req.body;
        await Limit3DigitTeng.updateOne(
            { number: req.params.number },
            { limit, amount },
            { upsert: true }
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/limits/3digit-teng/:number', async (req, res) => {
    try {
        await Limit3DigitTeng.deleteOne({ number: req.params.number });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.put('/api/limits/3digit-teng', async (req, res) => {
    try {
        const data = req.body;
        const bulkOps = Object.entries(data).map(([number, info]) => ({
            updateOne: {
                filter: { number },
                update: { limit: info.limit, amount: info.amount },
                upsert: true
            }
        }));
        await Limit3DigitTeng.bulkWrite(bulkOps);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== TRANSACTIONS API ====================
app.get('/api/transactions', async (req, res) => {
    try {
        const transactions = await Transaction.find().sort({ date: -1 });
        res.json(transactions.map(t => ({
            id: t._id,
            date: t.date,
            type: t.type,
            number: t.number,
            amount: t.amount,
            totalAmount: t.totalAmount,
            limit: t.limit
        })));
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/transactions', async (req, res) => {
    try {
        const { date, type, number, amount, totalAmount, limit } = req.body;
        const transaction = await Transaction.create({ date, type, number, amount, totalAmount, limit });
        res.json({ success: true, id: transaction._id });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/transactions/:id', async (req, res) => {
    try {
        await Transaction.deleteOne({ _id: req.params.id });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.delete('/api/transactions', async (req, res) => {
    try {
        await Transaction.deleteMany({});
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== EXPORT/IMPORT API ====================
app.get('/api/export', async (req, res) => {
    try {
        const users = await User.find();
        const settings = await Settings.findOne({ key: 'main' });
        const limits2digit = await Limit2Digit.find();
        const limits3digitTode = await Limit3DigitTode.find();
        const limits3digitTeng = await Limit3DigitTeng.find();
        const transactions = await Transaction.find();

        res.json({
            users: users.map(u => ({ username: u.username, password: u.password, createdAt: u.createdAt })),
            settings: settings ? {
                alertThreshold: settings.alertThreshold,
                defaultLimit2Digit: settings.defaultLimit2Digit,
                defaultLimit3DigitTode: settings.defaultLimit3DigitTode,
                defaultLimit3DigitTeng: settings.defaultLimit3DigitTeng
            } : {},
            limits2digit: limits2digit.map(l => ({ number: l.number, limit: l.limit, amount: l.amount })),
            limits3digitTode: limits3digitTode.map(l => ({ number: l.number, limit: l.limit, amount: l.amount })),
            limits3digitTeng: limits3digitTeng.map(l => ({ number: l.number, limit: l.limit, amount: l.amount })),
            transactions: transactions.map(t => ({
                id: t._id, date: t.date, type: t.type, number: t.number,
                amount: t.amount, totalAmount: t.totalAmount, limit: t.limit
            })),
            exportDate: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/import', async (req, res) => {
    try {
        const data = req.body;

        if (data.users) {
            await User.deleteMany({});
            await User.insertMany(data.users.map(u => ({
                username: u.username,
                password: u.password,
                createdAt: u.createdAt || new Date()
            })));
        }

        if (data.settings) {
            await Settings.updateOne({ key: 'main' }, {
                alertThreshold: data.settings.alertThreshold,
                defaultLimit2Digit: data.settings.defaultLimit2Digit,
                defaultLimit3DigitTode: data.settings.defaultLimit3DigitTode,
                defaultLimit3DigitTeng: data.settings.defaultLimit3DigitTeng
            });
        }

        if (data.limits2digit) {
            await Limit2Digit.deleteMany({});
            await Limit2Digit.insertMany(data.limits2digit);
        }

        if (data.limits3digitTode) {
            await Limit3DigitTode.deleteMany({});
            await Limit3DigitTode.insertMany(data.limits3digitTode);
        }

        if (data.limits3digitTeng) {
            await Limit3DigitTeng.deleteMany({});
            await Limit3DigitTeng.insertMany(data.limits3digitTeng);
        }

        if (data.transactions) {
            await Transaction.deleteMany({});
            await Transaction.insertMany(data.transactions.map(t => ({
                date: t.date, type: t.type, number: t.number,
                amount: t.amount, totalAmount: t.totalAmount, limit: t.limit
            })));
        }

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/clear-amounts', async (req, res) => {
    try {
        await Limit2Digit.updateMany({}, { amount: 0 });
        await Limit3DigitTode.updateMany({}, { amount: 0 });
        await Limit3DigitTeng.updateMany({}, { amount: 0 });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

app.post('/api/clear-all', async (req, res) => {
    try {
        await Limit2Digit.deleteMany({});
        await Limit3DigitTode.deleteMany({});
        await Limit3DigitTeng.deleteMany({});
        await Transaction.deleteMany({});

        // Re-initialize 2-digit
        const limits = [];
        for (let i = 0; i <= 99; i++) {
            const num = i.toString().padStart(2, '0');
            limits.push({ number: num, limit: 5000, amount: 0 });
        }
        await Limit2Digit.insertMany(limits);

        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// ==================== DATABASE INFO ====================
app.get('/api/db-info', async (req, res) => {
    try {
        const info = {
            type: 'MongoDB Atlas',
            connected: mongoose.connection.readyState === 1,
            tables: {
                users: await User.countDocuments(),
                limits_2digit: await Limit2Digit.countDocuments(),
                limits_3digit_tode: await Limit3DigitTode.countDocuments(),
                limits_3digit_teng: await Limit3DigitTeng.countDocuments(),
                transactions: await Transaction.countDocuments()
            }
        };
        res.json(info);
    } catch (err) {
        res.status(500).json({ success: false, message: err.message });
    }
});

// Start Server
initDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
        console.log(`Environment: ${FRONTEND_URL}`);
    });
});
