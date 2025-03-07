// server.js
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;

app.use(express.json());
app.use(cors({ origin: FRONTEND_URL }));

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log("Connected to MongoDB"))
.catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

app.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).json({ message: "All fields are required." });
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) return res.status(400).json({ message: "Username or email already exists." });
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ message: "Signup successful!" });
    } catch (error) {
        res.status(500).json({ message: "Server error. Please try again." });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ message: "All fields are required." });
        const user = await User.findOne({ $or: [{ username }, { email: username }] });
        if (!user) return res.status(400).json({ message: "Invalid credentials." });
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1h" });
        res.json({ message: "Login successful!", token });
    } catch (error) {
        res.status(500).json({ message: "Server error. Please try again." });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
