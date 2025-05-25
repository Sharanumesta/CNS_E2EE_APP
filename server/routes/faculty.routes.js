import express from "express";
import authMiddleware from "../middleware/auth.middleware.js";
import {
  getAssignedStudents,
  sendEncryptedMessages,
} from "../controllers/faculty.controller.js";

const router = express.Router();

// Admin route
router.get("/students", authMiddleware, getAssignedStudents);
router.post("/messages", authMiddleware, sendEncryptedMessages);

export default router;
  