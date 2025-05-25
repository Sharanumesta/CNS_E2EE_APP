import User from "../models/user.model.js";
import { generateKeys } from "../utils/crypto.utils.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

// Helper function to validate phone number
const validatePhoneNumber = (phone) => {
  const regex = /^[0-9]{10}$/;
  return regex.test(phone);
};

// Register a new user
export const registerUser = async (req, res) => {
  try {
    const {
      usn,
      employeeId,
      password,
      phoneNumber,
      department,
      role = "student",
      publicKey,
      encryptedPrivateKey,
      iv,
      salt,
    } = req.body;

    let identifier;
    if (role === "student") {
      identifier = usn;
      if (!identifier || !/^1NT\d{2}[A-Z]{2}\d{3}$/.test(identifier.trim().toUpperCase())) {
        return res.status(400).json({ error: "Invalid or missing USN format" });
      }
    } else if (role === "faculty") {
      identifier = employeeId;
      if (!identifier || !/^[A-Z]{2}\d{3}$/.test(identifier.trim().toUpperCase())) {
        return res.status(400).json({ error: "Invalid or missing employee ID format" });
      }
    } else {
      return res.status(400).json({ error: "Role must be 'student' or 'faculty'" });
    }

    if (!password || password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }

    if (!validatePhoneNumber(phoneNumber)) {
      return res.status(400).json({ error: "Invalid phone number format" });
    }

    if (!publicKey || !encryptedPrivateKey) {
      return res.status(400).json({ error: "Missing public or encrypted private key" });
    }

    // Build query dynamically based on role
    const query = role === "student" ? { usn: identifier.trim().toUpperCase() } : { employeeId: identifier.trim().toUpperCase() };

    const existingUser = await User.findOne(query);
    if (existingUser) {
      return res.status(400).json({ error: "User already exists" });
    }

    const bcryptSalt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, bcryptSalt);

    const newUser = new User({
      role,
      password: hashedPassword,
      publicKey,
      encryptedPrivateKey,
      iv,
      salt,
      department,
      phoneNumber,
      ...query,
    });

    await newUser.save();

    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: newUser._id,
        identifier,
        role: newUser.role,
        department: newUser.department,
      },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Server error during registration" });
  }
};



// Login user
export const loginUser = async (req, res) => {
  try {
    const { identifier, password, role } = req.body;
    if (!identifier || !password || !role) {
      return res.status(400).json({ error: "Identifier, password, and role are required." });
    }

    let user;
    if (role === "student") {
      user = await User.findOne({ usn: identifier });
    } else if (role === "faculty") {
      user = await User.findOne({ employeeId: identifier });
    } else {
      return res.status(400).json({ error: "Invalid role provided." });
    }

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Make sure user has iv and salt stored for both roles
    if (!user.encryptedPrivateKey || !user.iv || !user.salt) {
      return res.status(500).json({ error: "Missing encryption parameters for this user." });
    }

    res.status(200).json({
      message: "Login successful",
      token,
      encryptedPrivateKey: user.encryptedPrivateKey,
      iv: user.iv,
      salt: user.salt,
      user: {
        id: user._id,
        identifier,
        role: user.role,
        department: user.department,
        publicKey: user.publicKey,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Server error during login." });
  }
};


// Get user profile
export const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select(
      "-password -encryptedPrivateKey"
    );

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json(user);
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({ error: "Server error fetching profile" });
  }
};

// Get users by department (for faculty/admin)
export const getUsersByDepartment = async (req, res) => {
  try {
    // Only faculty and admin can access this
    if (req.user.role === "student") {
      return res.status(403).json({ error: "Unauthorized access" });
    }

    const { department } = req.params;
    const users = await User.find({ department }).select(
      "username role department phoneNumber"
    );

    res.json(users);
  } catch (error) {
    console.error("Department users error:", error);
    res.status(500).json({ error: "Server error fetching department users" });
  }
};

// Update user profile
export const updateUserProfile = async (req, res) => {
  try {
    const { phoneNumber, department } = req.body;

    // Validate phone number if provided
    if (phoneNumber && !validatePhoneNumber(phoneNumber)) {
      return res.status(400).json({ error: "Invalid phone number format" });
    }

    const updateData = {};
    if (phoneNumber) updateData.phoneNumber = phoneNumber;
    if (department) updateData.department = department;

    const updatedUser = await User.findByIdAndUpdate(req.user.id, updateData, {
      new: true,
    }).select("-password -encryptedPrivateKey");

    res.json({
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ error: "Server error updating profile" });
  }
};

// Admin-only: Get all users
export const getAllUsers = async (req, res) => {
  try {
    // Only admin can access this
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Unauthorized access" });
    }

    const users = await User.find().select("-password -encryptedPrivateKey");

    res.json(users);
  } catch (error) {
    console.error("Get all users error:", error);
    res.status(500).json({ error: "Server error fetching users" });
  }
};

// Admin-only: Update user role
export const updateUserRole = async (req, res) => {
  try {
    // Only admin can access this
    if (req.user.role !== "admin") {
      return res.status(403).json({ error: "Unauthorized access" });
    }

    const { userId } = req.params;
    const { role } = req.body;

    if (!["student", "faculty", "admin"].includes(role)) {
      return res.status(400).json({ error: "Invalid role specified" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select("-password -encryptedPrivateKey");

    if (!updatedUser) {
      return res.status(404).json({ error: "User not found" });
    }

    res.json({
      message: "User role updated successfully",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Role update error:", error);
    res.status(500).json({ error: "Server error updating role" });
  }
};
