const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const validator = require('validator'); // For email validation

const app = express();

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/Database')
  .then(() => console.log("Connected to Database"))
  .catch(err => {
    console.error("Error in Connecting to Database:", err);
    process.exit(1);  // Exit if the connection fails
  });

// Mongoose Schema and Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    age: { type: Number, required: true },
    email: { type: String, required: true, unique: true },
    phno: { type: String, required: true },
    gender: { type: String, required: true },
    password: { type: String, required: true }
});

const UserModel = mongoose.model('User', userSchema);

// Rate limiter setup for login and sign-up routes
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per window
    message: "Too many requests, please try again later"
});

// CREATE - Register a new user
app.post("/sign_up", limiter, async (req, res) => {
    const { name, age, email, phno, gender, password } = req.body;

    // Validate required fields
    if (!name || !age || !email || !phno || !gender || !password) {
        return res.status(400).json({ error: "All fields are required" });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: "Invalid email format" });
    }

    // Validate phone number format (assuming 10 digit phone number)
    const phoneRegex = /^\d{10}$/;
    if (!phoneRegex.test(phno)) {
        return res.status(400).json({ error: "Invalid phone number format" });
    }

    try {
        // Check if email already exists
        const existingUser = await UserModel.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: "Email already exists" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new UserModel({
            name,
            age,
            email,
            phno,
            gender,
            password: hashedPassword
        });

        await newUser.save();
        console.log("User created successfully");
        return res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        console.error("Error creating user:", err);
        return res.status(500).json({ error: "Error creating user", details: err.message });
    }
});

// LOGIN - Authenticate user
app.post("/login", limiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });

        return res.status(200).json({ message: "Login successful", token });
    } catch (err) {
        console.error("Error logging in:", err);
        return res.status(500).json({ error: "Error logging in" });
    }
});

// READ - Get all users
app.get("/users", async (req, res) => {
    try {
        const users = await UserModel.find({});
        res.json(users);
    } catch (err) {
        console.error("Error fetching users:", err);
        return res.status(500).json({ error: "Error fetching users" });
    }
});

// READ - Get a single user by ID
app.get("/users/:id", async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await UserModel.findById(userId);

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json(user);
    } catch (err) {
        console.error("Error fetching user:", err);
        return res.status(500).json({ error: "Error fetching user" });
    }
});

// UPDATE - Update a user by ID
app.put("/users/:id", async (req, res) => {
    try {
        const userId = req.params.id;
        const { name, age, email, phno, gender, password } = req.body;

        const updatedData = { name, age, email, phno, gender };

        if (password) {
            updatedData.password = await bcrypt.hash(password, 10);
        }

        const updatedUser = await UserModel.findByIdAndUpdate(userId, updatedData, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ error: "User not found or no changes made" });
        }

        res.json({ message: "User updated successfully", updatedUser });
    } catch (err) {
        console.error("Error updating user:", err);
        return res.status(500).json({ error: "Error updating user" });
    }
});

// DELETE - Delete a user by ID
app.delete("/users/:id", async (req, res) => {
    try {
        const userId = req.params.id;
        const deletedUser = await UserModel.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ message: "User deleted successfully" });
    } catch (err) {
        console.error("Error deleting user:", err);
        return res.status(500).json({ error: "Error deleting user" });
    }
});

// Home route
app.get("/", (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);
});
