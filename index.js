const express = require('express');
const app = express();
const data = require('./data.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const users = require('./users.js'); // Assuming you have a users.js file with user data
const cors = require('cors');
const { StatusCodes } = require('http-status-codes');
// Middleware to parse JSON requests
app.use(express.json());
app.use(cors());
require('dotenv').config();
// route for getting recent studyLogs

const authenticateToken = async (req, res, next) => {
    const error = new Error();
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        error.message = 'Access token required';
        throw error;
    }
    console.log('Token received:', token);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            error.message = 'Invalid token or token expired';
            throw error;
        }else {
            console.log('User:', user);
            req.user = user;
            next()
        }
    });
};

// route for gettiing all the studyLogs
app.get('/api/studyLogs', authenticateToken, async (req, res) => {
    const userLogs = data.filter(log => log.userId === parseInt(req.user.id));
    res.json(userLogs)
});


app.get('/api/studyLogs/recent', authenticateToken, async (req, res) => {
    const limit = 2
    const userLogs = data.filter(log => log.userId === parseInt(req.user.id))
    const recent = [...userLogs] // copy the array so you don't mutate the original
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, limit);
    res.json(recent);
});



// route for getting a specific studyLog by id
app.get('/api/studyLogs/:id', authenticateToken, (req, res) => {
    const id = parseInt(req.params.id);
    const userLogs = data.filter(log => log.userId === parseInt(req.user.id));
    const studyLog = userLogs.find(log => log.id === id);
    res.json(studyLog);
});

// login
app.post('/api/login', async (req, res) => {
    const error = new Error();
    const { email, password } = req.body;
    const authHeader = req.headers['authorization'];
    const existingtoken = authHeader && authHeader.split(' ')[1];
    console.log('Existing token:', existingtoken);
    // if
    const isValidToken = existingtoken && await jwt.verify(existingtoken, process.env.JWT_SECRET);
    if (isValidToken) {
        error.message = 'User already logged in';
        throw error;
    }
    if(!email || !password) {
        error.message = 'email and password are required';
        throw error;
    }
    const user = users.find((u) => u.email === email);
    if (!user) {
        error.message = 'User not found';
        throw error;
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        error.message = 'Invalid password';
        throw error;
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET);
    res.status(200).json({ message: 'Login successful', token });
});
app.post('/api/signup', async (req, res) => {
    const error = new Error();
    const { email, username, password } = req.body;
    const authHeader = req.headers['authorization'];
    const existingtoken = authHeader && authHeader.split(' ')[1];
    const isValidToken = existingtoken && await jwt.verify(existingtoken, process.env.JWT_SECRET);
    if (isValidToken) {
        error.message = 'User already logged in';
        throw error;
    }
    if (!email || !username || !password) {
        error.status = StatusCodes.NO_CONTENT;
        error.message = 'Email, username, and password are required';
        throw error;
    }
    const existingUser = users.find((u) => u.email === email);
    if (existingUser) {
        error.message = 'User already exists';
        throw error;
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = { email, username, password: hashedPassword };
    users.push(newUser);
    res.status(StatusCodes.CREATED).json({ message: 'User created successfully', user: newUser });
});
app.post('/api/create', authenticateToken, async (req, res) => {
    const { subject, hoursStudied, notes, status } = req.body;
    const error = new Error();
    if (!subject || !hoursStudied || !status) {
        error.message = 'Subject, hoursStudied, and status are required';
        throw error;
    }
    const newStudyLog = {
        id: data.length + 1,
        userId: parseInt(req.user.id),
        subject,
        hoursStudied,
        notes,
        status
    };
    data.push(newStudyLog);
    res.status(StatusCodes.CREATED).json({ message: 'Study log created successfully', studyLog: newStudyLog });
});
app.patch('/api/studyLogs/:id', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    const { subject, hoursStudied, notes, status } = req.body;
    const error = new Error();
    const userLogs = data.filter(log => log.userId === parseInt(req.user.id));
    const studyLogIndex = userLogs.findIndex(log => log.id === id);
    if (studyLogIndex === -1) {
        error.message = 'Study log not found';
        throw error;
    }
    if (subject) {
        data[studyLogIndex].subject = subject;
    }
    if (hoursStudied) {
        data[studyLogIndex].hoursStudied = hoursStudied;
    }
    if (notes) {
        data[studyLogIndex].notes = notes;
    }
    if (status) {
        data[studyLogIndex].status = status;
    }
    res.status(StatusCodes.OK).json({ message: 'Study log updated successfully', studyLog: data[studyLogIndex] });
});
app.use((err, req, res, next) => {
    const message = err.message || 'Internal Server Error';
    res.status(err.status || StatusCodes.INTERNAL_SERVER_ERROR).send(message);
});
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});

