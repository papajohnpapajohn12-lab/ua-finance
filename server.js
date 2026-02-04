const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'pajohn-secret-key-10x';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: { error: 'Забагато спроб входу. Спробуйте через 15 хвилин.' }
});

app.use('/api/login', loginLimiter);

// Health check endpoint for uptime monitoring
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

const db = new sqlite3.Database('./finance.db');

// Schema Init
db.serialize(() => {
    // Ensure tables exist. We dropped them before, so now they should be there or created.
    // To be safe against corruption, we won't drop again unless necessary.
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, 
        user_id INTEGER, 
        type TEXT, 
        amount REAL, 
        original_amount REAL,
        currency TEXT, 
        category TEXT, 
        date TEXT, 
        stash_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        name TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(user_id, type, name)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS stashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        target_amount REAL,
        current_amount REAL DEFAULT 0,
        currency TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Migration: Add theme column if not exists
    db.all("PRAGMA table_info(users)", (err, rows) => {
        if (!rows.some(r => r.name === 'theme')) {
            db.run("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'light'");
        }
    });
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, row) => {
        if (row) return res.status(409).json({ error: 'USER_EXISTS' });
        db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, bcrypt.hashSync(password, 8)], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ token: jwt.sign({ id: this.lastID, username }, SECRET_KEY) });
        });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
        if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'WRONG_PASSWORD' });
        res.json({ token: jwt.sign({ id: user.id, username: user.username }, SECRET_KEY), theme: user.theme || 'light' });
    });
});

app.post('/api/user/theme', authenticateToken, (req, res) => {
    const { theme } = req.body;
    db.run(`UPDATE users SET theme = ? WHERE id = ?`, [theme, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.get('/api/transactions', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC`, [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});

app.post('/api/transactions', authenticateToken, (req, res) => {
    const { type, amount, original_amount, currency, category, stash_id } = req.body;
    const date = new Date().toISOString();

    if (amount < 0) return res.status(400).json({ error: 'NEGATIVE_AMOUNT' });

    const proceed = () => {
        db.run(`INSERT OR IGNORE INTO categories (user_id, type, name) VALUES (?, ?, ?)`, [req.user.id, type, category], () => {
            db.run(`INSERT INTO transactions (user_id, type, amount, original_amount, currency, category, date, stash_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, 
                [req.user.id, type, amount, original_amount, currency, category, date, stash_id || null], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID, type, amount, category, date });
            });
        });
    };

    if (type === 'expense') {
        db.all(`SELECT type, amount FROM transactions WHERE user_id = ?`, [req.user.id], (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            const balance = (rows || []).reduce((acc, t) => t.type === 'income' ? acc + t.amount : acc - t.amount, 0);
            if (balance < amount) return res.status(400).json({ error: 'NO_FUNDS' });
            proceed();
        });
    } else {
        proceed();
    }
});

app.delete('/api/transactions/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM transactions WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], function(err) {
        if (this.changes > 0) res.json({ success: true });
        else res.status(404).json({ error: 'Not found' });
    });
});

app.get('/api/categories', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM categories WHERE user_id = ?`, [req.user.id], (err, rows) => res.json(rows || []));
});

app.delete('/api/categories/:id', authenticateToken, (req, res) => {
    db.run(`DELETE FROM categories WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], () => res.json({ success: true }));
});

app.get('/api/stashes', authenticateToken, (req, res) => {
    db.all(`SELECT * FROM stashes WHERE user_id = ?`, [req.user.id], (err, rows) => res.json(rows || []));
});

app.post('/api/stashes', authenticateToken, (req, res) => {
    const { title, target_amount, currency } = req.body;
    db.run(`INSERT INTO stashes (user_id, title, target_amount, currency) VALUES (?, ?, ?, ?)`, 
        [req.user.id, title, target_amount, currency], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, title, target_amount, current_amount: 0, currency });
    });
});

app.post('/api/stashes/:id/add', authenticateToken, (req, res) => {
    const { amount, uah_amount } = req.body; 
    db.all(`SELECT type, amount FROM transactions WHERE user_id = ?`, [req.user.id], (err, rows) => {
        const balance = (rows||[]).reduce((acc, t) => t.type === 'income' ? acc + t.amount : acc - t.amount, 0);
        if (balance < uah_amount) return res.status(400).json({ error: 'NO_FUNDS' });

        const date = new Date().toISOString();
        db.run(`INSERT INTO transactions (user_id, type, amount, category, date, stash_id) VALUES (?, 'expense', ?, ?, ?, ?)`,
            [req.user.id, uah_amount, 'Заначка', date, req.params.id], function(err) {
            db.run(`UPDATE stashes SET current_amount = current_amount + ? WHERE id = ?`, [amount, req.params.id], () => res.json({ success: true }));
        });
    });
});

app.post('/api/stashes/:id/break', authenticateToken, (req, res) => {
    db.get(`SELECT current_amount, currency FROM stashes WHERE id = ?`, [req.params.id], (err, stash) => {
        if (!stash) return res.status(404).json({ error: 'Not found' });
        let refund = stash.current_amount;
        if (stash.currency === 'USDT') refund = refund * 43; // Hardcoded rate for now

        const date = new Date().toISOString();
        db.run(`INSERT INTO transactions (user_id, type, amount, category, date) VALUES (?, 'income', ?, 'Розбита заначка', ?)`,
            [req.user.id, refund, date], () => {
            db.run(`DELETE FROM stashes WHERE id = ?`, [req.params.id], () => res.json({ success: true }));
        });
    });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
