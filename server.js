require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require('cors');



const app = express();
app.use(cors());
app.use(express.json());

// 🛠 Database Connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.message);
    } else {
        console.log("✅ Database connected!");
    }
});

// 🛠 User Registration API
app.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    // Check if user exists
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (results.length > 0) {
            return res.status(400).json({ error: "Email already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
        db.query(sql, [name, email, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ message: "User registered successfully!" });
        });
    });
});

// 🛠 User Login API
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (results.length === 0) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        // Generate JWT Token (without role)
        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });

        // Update last login
        db.query("UPDATE users SET last_login_at = NOW(), ip_address = ? WHERE id = ?", [req.ip, user.id]);

        res.json({ message: "Login successful", token });
    });
});

// 🛠 Protected Route (Dashboard)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    if (!authHeader) return res.status(401).json({ error: "Access denied, no token provided" });

    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

app.get("/dashboard", authenticateToken, (req, res) => {
    db.query("SELECT id, name, email FROM users WHERE id = ?", [req.user.id], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json({ message: "Welcome to the dashboard", user: results[0] });
    });
});

const multer = require("multer");
const path = require("path");

// Set Storage Engine
const storage = multer.diskStorage({
    destination: "./uploads/videos",
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Unique file name
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 100 * 1024 * 1024 }, // 100MB limit
    fileFilter: (req, file, cb) => {
        const fileTypes = /mp4|mkv|avi/;
        const mimetype = fileTypes.test(file.mimetype);
        if (mimetype) {
            cb(null, true);
        } else {
            cb(new Error("Only video files are allowed!"));
        }
    },
});

// API to Upload Video (Stores File Path in DB)
app.post("/upload", authenticateToken, upload.single("video"), (req, res) => {
    const { title, description } = req.body;
    const videoPath = req.file?.path.replace(/\\/g, "/");

    if (!title || !description || !videoPath) {
        return res.status(400).json({ error: "All fields are required" });
    }

    db.query(
        "INSERT INTO videos (title, description, video, user_id) VALUES (?, ?, ?, ?)",
        [title, description, videoPath, req.user.id],
        (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: "Video uploaded successfully!", videoPath });
        }
    );
});



app.get("/video/:id", (req, res) => {
    const videoId = req.params.id;

    db.query("SELECT video FROM videos WHERE id = ?", [videoId], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: "Video not found" });

        const videoPath = results[0].video;
        res.sendFile(path.resolve(videoPath)); // Serve the file
    });
});

app.get("/videos", (req, res) => {
    db.query("SELECT id, title, video FROM videos", (err, results) => {
        if (err) return res.status(500).json({ error: err.message });

        res.json(results); // Return all videos as JSON
    });
});


// 🛠 Server Listen
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
