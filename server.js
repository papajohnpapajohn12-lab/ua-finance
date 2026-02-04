require('dotenv').config();
const express = require('express');
const { createClient } = require('@libsql/client');
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

const client = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Helper to wrap Turso execute in Promise is not needed as it returns Promise, 
// but we need to adapt the callback style of sqlite3 to async/await for Turso.

async function initDb() {
    await client.execute(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
    await client.execute(`CREATE TABLE IF NOT EXISTS transactions (
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
    await client.execute(`CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        name TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        UNIQUE(user_id, type, name)
    )`);
    await client.execute(`CREATE TABLE IF NOT EXISTS stashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        title TEXT,
        target_amount REAL,
        current_amount REAL DEFAULT 0,
        currency TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    
    // Migration: Add theme column if not exists
    try {
        const rs = await client.execute("SELECT theme FROM users LIMIT 1");
    } catch (e) {
        if (e.message.includes("no such column")) {
             await client.execute("ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'light'");
        }
    }
}

initDb().catch(console.error);

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const rs = await client.execute({sql: `SELECT id FROM users WHERE username = ?`, args: [username]});
        if (rs.rows.length > 0) return res.status(409).json({ error: 'USER_EXISTS' });
        
        const insert = await client.execute({
            sql: `INSERT INTO users (username, password, theme) VALUES (?, ?, 'light') RETURNING id`, 
            args: [username, bcrypt.hashSync(password, 8)]
        });
        const newId = insert.rows[0].id; // RETURNING id is supported in Turso/libSQL
        res.json({ token: jwt.sign({ id: newId, username }, SECRET_KEY) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const rs = await client.execute({sql: `SELECT * FROM users WHERE username = ?`, args: [username]});
        const user = rs.rows[0];
        if (!user) return res.status(404).json({ error: 'USER_NOT_FOUND' });
        if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'WRONG_PASSWORD' });
        res.json({ token: jwt.sign({ id: user.id, username: user.username }, SECRET_KEY), theme: user.theme || 'light' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/user/theme', authenticateToken, async (req, res) => {
    const { theme } = req.body;
    try {
        await client.execute({sql: `UPDATE users SET theme = ? WHERE id = ?`, args: [theme, req.user.id]});
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/transactions', authenticateToken, async (req, res) => {
    try {
        const rs = await client.execute({sql: `SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC`, args: [req.user.id]});
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/transactions', authenticateToken, async (req, res) => {
    const { type, amount, original_amount, currency, category, stash_id } = req.body;
    const date = new Date().toISOString();

    if (amount < 0) return res.status(400).json({ error: 'NEGATIVE_AMOUNT' });

    try {
        if (type === 'expense') {
            const rs = await client.execute({sql: `SELECT type, amount FROM transactions WHERE user_id = ?`, args: [req.user.id]});
            const balance = rs.rows.reduce((acc, t) => t.type === 'income' ? acc + t.amount : acc - t.amount, 0);
            if (balance < amount) return res.status(400).json({ error: 'NO_FUNDS' });
        }

        await client.execute({sql: `INSERT OR IGNORE INTO categories (user_id, type, name) VALUES (?, ?, ?)`, args: [req.user.id, type, category]});
        
        const insert = await client.execute({
            sql: `INSERT INTO transactions (user_id, type, amount, original_amount, currency, category, date, stash_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`, 
            args: [req.user.id, type, amount, original_amount, currency, category, date, stash_id || null]
        });
        
        res.json({ id: insert.rows[0].id, type, amount, category, date });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/:id', authenticateToken, async (req, res) => {
    try {
        const rs = await client.execute({sql: `DELETE FROM transactions WHERE id = ? AND user_id = ?`, args: [req.params.id, req.user.id]});
        if (rs.rowsAffected > 0) res.json({ success: true });
        else res.status(404).json({ error: 'Not found' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/categories', authenticateToken, async (req, res) => {
    try {
        const rs = await client.execute({sql: `SELECT * FROM categories WHERE user_id = ?`, args: [req.user.id]});
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
    try {
        await client.execute({sql: `DELETE FROM categories WHERE id = ? AND user_id = ?`, args: [req.params.id, req.user.id]});
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/stashes', authenticateToken, async (req, res) => {
    try {
        const rs = await client.execute({sql: `SELECT * FROM stashes WHERE user_id = ?`, args: [req.user.id]});
        res.json(rs.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stashes', authenticateToken, async (req, res) => {
    const { title, target_amount, currency } = req.body;
    try {
        const insert = await client.execute({
            sql: `INSERT INTO stashes (user_id, title, target_amount, currency) VALUES (?, ?, ?, ?) RETURNING id`, 
            args: [req.user.id, title, target_amount, currency]
        });
        res.json({ id: insert.rows[0].id, title, target_amount, current_amount: 0, currency });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stashes/:id/add', authenticateToken, async (req, res) => {
    const { amount, uah_amount } = req.body; 
    try {
        const rs = await client.execute({sql: `SELECT type, amount FROM transactions WHERE user_id = ?`, args: [req.user.id]});
        const balance = rs.rows.reduce((acc, t) => t.type === 'income' ? acc + t.amount : acc - t.amount, 0);
        if (balance < uah_amount) return res.status(400).json({ error: 'NO_FUNDS' });

        const date = new Date().toISOString();
        await client.execute({
            sql: `INSERT INTO transactions (user_id, type, amount, category, date, stash_id) VALUES (?, 'expense', ?, ?, ?, ?)`,
            args: [req.user.id, uah_amount, 'Заначка', date, req.params.id]
        });
        await client.execute({
            sql: `UPDATE stashes SET current_amount = current_amount + ? WHERE id = ?`, 
            args: [amount, req.params.id]
        });
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/stashes/:id/break', authenticateToken, async (req, res) => {
    try {
        const rs = await client.execute({sql: `SELECT current_amount, currency FROM stashes WHERE id = ?`, args: [req.params.id]});
        const stash = rs.rows[0];
        if (!stash) return res.status(404).json({ error: 'Not found' });
        
        let refund = stash.current_amount;
        if (stash.currency === 'USDT') refund = refund * 43; // Hardcoded rate

        const date = new Date().toISOString();
        await client.execute({
            sql: `INSERT INTO transactions (user_id, type, amount, category, date) VALUES (?, 'income', ?, 'Розбита заначка', ?)`,
            args: [req.user.id, refund, date]
        });
        await client.execute({sql: `DELETE FROM stashes WHERE id = ?`, args: [req.params.id]});
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:3000`));
