const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require('bcrypt');

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

// CREATE - Register a new user
app.post("/sign_up", async (req, res) => {
    try {
        const { name, age, email, phno, gender, password } = req.body;
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
        return res.status(500).json({ error: "Error creating user" });
    }
});

// LOGIN - Authenticate user
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find user by email
        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Compare passwords
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: "Invalid password" });
        }

        // Passwords match, login successful
        return res.status(200).json({ message: "Login successful" });
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

        // Create an object to hold the updated data
        const updatedData = {
            name,
            age,
            email,
            phno,
            gender
        };

        // Only hash and include the password if it is provided
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
    res.sendFile(__dirname + '/public/index.html');
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}`);  // Corrected string interpolation
});
