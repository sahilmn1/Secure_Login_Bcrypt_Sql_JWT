const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const port = 3000;
const secretKey = "findfbFCDSm1558";
app.use(bodyParser.json());
app.use(cors());

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  console.log("Request headers:", req.headers);
  const token = req.headers["authorization"];

  if (!token) {
    console.log("auth failed: Token not provided");
    return res.status(401).json({ error: "Unauthorized: Token not provided" });
  }

  jwt.verify(token.split(" ")[1], secretKey, (err, decoded) => {
    if (err) {
      console.error("unoth failed:", err.message);
      console.log(secretKey);
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }

    req.user = decoded.username;
    next();
  });
};

// Database connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "login",
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("Connected to database");
});
const salt = 10;

// User registration endpoint
app.post("/signup", (req, res) => {
  const { username, password } = req.body;

  // Hash the password
  bcrypt.hash(password.toString(), salt, (err, hash) => {
    if (err) {
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }

    // Store hashed password in the database
    db.query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
      (err, result) => {
        if (err) {
          res.status(500).json({ error: "Internal Server Error" });
          return;
        }
        res.status(201).json({ message: "User registered successfully" });
      }
    );
  });
});

// User login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  console.log("Login attempt for username:", username);

  // Find user by username
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, results) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).json({ error: "Internal Server Error" });
      }

      console.log("Database results:", results);

      if (results.length === 0) {
        console.log("User not found:", username);
        return res.status(401).json({ error: "Invalid username or password" });
      }

      // Compare hashed password
      const storedHashedPassword = results[0].password;
      console.log("Stored hashed password:", storedHashedPassword);
      console.log("Password provided during login:", password);

      // Hash the password provided during login for comparison
      bcrypt.compare(
        password.toString(),
        storedHashedPassword,
        (compareErr, result) => {
          if (compareErr) {
            console.error("Password comparison error:", compareErr);
            return res.status(500).json({ error: "Internal Server Error" });
          }

          console.log("bcrypt comparison result:", result);

          if (!result) {
            console.log("Incorrect password for user:", username);
            return res
              .status(401)
              .json({ error: "Invalid username or password" });
          }

          // Generate JWT token
          const token = jwt.sign({ username }, secretKey, {
            expiresIn: "1h",
          });

          res.status(200).json({ token });
        }
      );
    }
  );
});

// Protected routes
app.get("/about", verifyToken, (req, res) => {
  res.json({ message: "This is the about page" });
});

app.get("/contact", verifyToken, (req, res) => {
  res.json({ message: "This is the contact page" });
});

app.get("/help", verifyToken, (req, res) => {
  res.json({ message: "This is the help page" });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
