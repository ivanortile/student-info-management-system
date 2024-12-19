require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');  
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');


const app = express();
app.use(cors());
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, '../frontend')));

const db = mysql.createConnection({
    host: process.env.DB_HOST, 
    user: process.env.DB_USER, 
    password: process.env.DB_PASSWORD, 
    database: process.env.DB_NAME 
});

// Connect to the database
db.connect((err) => {  
    if (err) {
        console.error('Database connection failed:', err);
    } else {
        console.log('Database connected!');
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'form.html'));
});
//registration//
app.post('/api/auth/register', (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const sql = 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)';
    db.query(sql, [username, hashedPassword, role], (err, result) => {
        if (err) {
            console.error('Error registering user:', err);
            return res.status(500).json({ message: 'Error registering user.' });
        }
        res.status(201).json({ message: 'User registered successfully!' });
    });
});
//login form//
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';

    db.query(sql, [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Error logging in.' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const user = results[0];
        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid password.' });
        }

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'Login successful!', token, role: user.role }); // Send role back to frontend
    });
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).json({ message: 'Token required' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });
        req.user = decoded;  // Store user data in request
        next();
    });
};

// Dashboard route//
app.get('/dashboard', verifyToken, (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend', 'dashboard.html'));
});

app.post('/api/students', verifyToken, (req, res) => {
    const { name, course } = req.body;
    const sql = 'INSERT INTO students (name, course) VALUES (?, ?)';

    db.query(sql, [name, course], (err, result) => {
        if (err) {
            console.error('Error adding student:', err);
            return res.status(500).json({ message: 'Error adding student.' });
        }
        res.status(201).json({ message: 'Student added successfully!' });
    });
});
// students dashboard//
app.get('/api/students', verifyToken, (req, res) => {
    const sql = 'SELECT * FROM students';

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching students:', err);
            return res.status(500).json({ message: 'Error fetching students.' });
        }
        res.json(results); 
    });
});

app.put('/api/students/:id', verifyToken, (req, res) => {
    const { name, course } = req.body;
    const sql = 'UPDATE students SET name = ?, course = ? WHERE id = ?';

    db.query(sql, [name, course, req.params.id], (err, result) => {
        if (err) {
            console.error('Error editing student:', err);
            return res.status(500).json({ message: 'Error editing student.' });
        }
        res.json({ message: 'Student updated successfully!' });
    });
});

app.delete('/api/students/:id', verifyToken, (req, res) => {
    const sql = 'DELETE FROM students WHERE id = ?';

    db.query(sql, [req.params.id], (err, result) => {
        if (err) {
            console.error('Error deleting student:', err);
            return res.status(500).json({ message: 'Error deleting student.' });
        }
        res.json({ message: 'Student deleted successfully!' });
    });
});

// Add an announcement route (Admin only)
app.post('/api/announcements', verifyToken, (req, res) => {
    const { title, content } = req.body;

    if (req.user.role !== 'Admin') {
        return res.status(403).json({ message: 'Unauthorized' });
    }

    const sql = 'INSERT INTO announcements (title, content) VALUES (?, ?)';

    db.query(sql, [title, content], (err, result) => {
        if (err) {
            console.error('Error adding announcement:', err);
            return res.status(500).json({ message: 'Error adding announcement.' });
        }
        res.status(201).json({ message: 'Announcement added successfully!' });
    });
});
// Get all announcements route
app.get('/api/announcements', verifyToken, (req, res) => {
    const sql = 'SELECT * FROM announcements ORDER BY created_at DESC';

    db.query(sql, (err, results) => {
        if (err) {
            console.error('Error fetching announcements:', err);
            return res.status(500).json({ message: 'Error fetching announcements.' });
        }
        res.json(results); 
    });
});


app.listen(3001, () => {
    console.log('Server running on http://localhost:3001');
});
