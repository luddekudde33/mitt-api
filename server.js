require('dotenv').config();
const bcrypt = require('bcryptjs');
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

app.listen(3000, () => {
    console.log('Servern är igång på port 3000');
});

function getConnection() {
    return pool.promise();
}


    function authenticateToken(req, res, next) {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
    
        if (!token) {
            return res.status(401).json({ message: "No token provided" });
        }
    
        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.status(403).json({ message: "Token is not valid" });
            }
            req.user = user;
            next();
        });
    }
    
app.get('/users', authenticateToken, async (req, res) => {
    try {
        const connection = await getConnection();
        const [rows] = await connection.query('SELECT id, username, first_name, last_name FROM users');
        res.json(rows);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


app.post('/users', authenticateToken, async (req, res) => {
    try {
        const { username, first_name, last_name, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const connection = await getConnection();
        const [result] = await connection.execute(
            'INSERT INTO users (username, first_name, last_name, password) VALUES (?, ?, ?, ?)',
            [username, first_name, last_name, hashedPassword]
        );

        res.status(201).json({ id: result.insertId });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


app.get('/users/:id', authenticateToken, async (req, res) => {
    try {
        const connection = await getConnection();
        const [rows] = await connection.query('SELECT id, username, first_name, last_name FROM users WHERE id = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Användare inte hittad.' });
        }
        res.json(rows[0]);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


app.put('/users/:id', authenticateToken, async (req, res) => {
    try {
        const { username, first_name, last_name, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await getConnection();
        await connection.execute(
            'UPDATE users SET username = ?, first_name = ?, last_name = ?, password = ? WHERE id = ?',
            [username, first_name, last_name, hashedPassword, req.params.id]
        );
        res.json({ message: 'Användare uppdaterad', id: req.params.id });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const connection = await getConnection();
        const [users] = await connection.query('SELECT * FROM users WHERE username = ?', [username]);

        if (users.length === 0) {
            return res.status(401).json({ message: 'Ogiltigt användarnamn eller lösenord' });
        }

        const user = users[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Ogiltigt användarnamn eller lösenord' });
        }

        const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});


app.get('/', (req, res) => {
    res.json({
        message: 'Välkommen till mitt API!',
        routes: {
            "/users": "GET: Hämta alla användare, POST: Skapa en ny användare",
            "/users/:id": "GET: Hämta, PUT: Uppdatera en befintlig användare",
            "/login": "POST: Logga in och få en JWT",
            "/protected": "GET: Exempel på en skyddad route som kräver JWT"
        }
    });
});
