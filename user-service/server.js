const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");

dotenv.config();

const app = express();
app.use(express.json());

const uri =
  "mongodb+srv://maxtac:maxtac5960@cluster0.o3so0.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

 async function createDBConnection() {
    try {
      console.log("connecting to db...");
      dbConnection = await mongoose.connect(uri);
      console.log("Connected to the database");
      return dbConnection;
    } catch (error) {
      console.error(`Error connecting to the database. n${error}`);
    }
  }

  async function closeDBConnection() {
    try {
      dbConnection.disconnect();
      console.log("successfully connection closed");
    } catch (error) {
      console.error(`Error disconneting from the database. n${error}`);
    }
  }

  createDBConnection();

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

const secretKey = process.env.JWT_SECRET || "your_secret_key"; // Replace with a strong secret key

app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ message: "Username already exists" });
    } else {
      res
        .status(500)
        .json({ message: "Registration failed", error: error.message });
    }
  }
});

app.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    if (!user) {
      return res.status(401).json({ message: "Authentication failed" });
    }

    const passwordMatch = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!passwordMatch) {
      return res.status(401).json({ message: "Authentication failed" });
    }

    const token = jwt.sign({id: user._id, username: user.username }, secretKey, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error: error.message });
  }
});

// Protected Route Example (Middleware)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Protected route accessed", user: req.user });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
