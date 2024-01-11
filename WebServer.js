// WebServer Javascript.js
const express = require('express');
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');

const app = express();

// Middleware
app.use(bodyParser.json());

//token verification middleware
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized - Token not provided' });
    }

    jwt.verify(token.replace('Bearer ', ''), jwtOptions.secretOrKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized - Invalid token' });
        }

        req.userId = decoded.sub;
        next();
    });
};

// Database connection
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'snsaOm@99702641',
    database: 'users',
});

// Passport setup
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'm4p1e',
};

passport.use(new JwtStrategy(jwtOptions, async (payload, done) => {
    try {
        // Check if user exists in the database using payload subfield (user ID)
        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [payload.sub]);

        if (rows.length > 0) {
            return done(null, rows[0]);
        } else {
            return done(null, false);
        }
    } catch (error) {
        return done(error, false);
    }
}));

// Routes

// User registration route
app.route('/signup')
    .get((req, res) => {
        // Welcome message for user registration page
        res.send('Welcome to the user registration page! To create an account, make a POST request to this endpoint with your name, username, and password.');
    })
    .post(async (req, res) => {
        try {
            const { name, username, password } = req.body;

            // Hash the password
            const hashedPassword = await bcrypt.hash(password, 10);

            // Use parameterized query to prevent SQL injection
            await db.query('INSERT INTO users (name, username, password) VALUES (?, ?, ?)', [name, username, hashedPassword]);

            res.status(201).json({ message: 'User registered successfully' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    });

// User login route
app.route('/login')
    .get((req, res) => {
        // Welcome message for user login page
        res.send('Welcome to the user login page! To log in, make a POST request to this endpoint with your username and password.');
    })
    .post(async (req, res) => {
        try {
            const { username, password } = req.body;

            // Use parameterized query to prevent SQL injection
            const [rows] = await db.query('SELECT * FROM users WHERE username = ?', [username]);

            if (rows.length === 0) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            // Compare the provided password with the stored hashed password
            const isPasswordValid = await bcrypt.compare(password, rows[0].password);

            if (!isPasswordValid) {
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            // Generate a JWT token for authentication with a 15-minute expiration time
            const token = jwt.sign({ sub: rows[0].id }, jwtOptions.secretOrKey, { expiresIn: '1h' });


            // Respond with the token
            res.json({ token });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    });

// Create post route
app.route('/createpost')
    .get((req, res) => {
        // Welcome message for create post page
        res.send('Welcome to the create post page! To create a post, make a POST request to this endpoint with your post title and details. You need to be logged in, so include a valid token in the Authorization header.');
    })
    .post(verifyToken, async (req, res) => {
        try {
            // Ensure that only authenticated users can access this route
            const userId = req.userId;

            const { title, details } = req.body;

            // Use parameterized query to prevent SQL injection
            await db.query('INSERT INTO posts (title, details, userId) VALUES (?, ?, ?)', [title, details, userId]);

            res.json({ message: 'Post created successfully' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal Server Error' });
        }
    });

// Get post route
app.get('/getpost', verifyToken, async (req, res) => {
    try {
        // Ensure that only authenticated users can access this route
        const userId = req.userId;

        // Retrieve posts associated with the user ID from the database
        const [rows] = await db.query('SELECT * FROM posts WHERE userId = ?', [userId]);

        // Structure the response in a well-formatted way
        const formattedPosts = rows.map(post => ({
            postId: post.id,
            title: post.title,
            details: post.details,
            // Add any other fields you want to include
        }));

        res.json({ message: 'Posts retrieved successfully', posts: formattedPosts });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Start server on port 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));

