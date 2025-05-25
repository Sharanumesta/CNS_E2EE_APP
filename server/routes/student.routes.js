import express from "express";
import { fetchMessages } from "../controllers/student.controller.js";
import authMiddleware from "../middleware/auth.middleware.js";

const router = express.Router();

router.get("/messages", authMiddleware, fetchMessages);
router.get("/test", (req, res) => {
  res.json({ message: "Student router is working!" });
});

export default router;
