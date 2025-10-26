const express = require("express");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");
const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./users.db");
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.run(
    `INSERT INTO users(email,password) VALUES(?,?)`,
    [email, hashed],
    (err) => {
      if (err) return res.status(400).json({ error: "Email already exists" });
      res.json({ success: true });
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, row) => {
    if (!row || !(await bcrypt.compare(password, row.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    res.json({ success: true });
  });
});

app.get("/stats", (req, res) => {
  db.all(
    `SELECT DATE(created_at) as date, COUNT(*) as count
     FROM users
     GROUP BY DATE(created_at)
     ORDER BY DATE(created_at) DESC
     LIMIT 30`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
