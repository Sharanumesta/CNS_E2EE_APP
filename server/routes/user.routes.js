import express from "express";
import {
  registerUser,
  loginUser,
  getUserProfile,
  getUsersByDepartment,
  updateUserProfile,
  getAllUsers,
  updateUserRole,
} from "../controllers/auth.controller.js";

const router = express.Router();

// Public routes
router.post("/register", registerUser);
router.post("/login", loginUser);

export default router;
