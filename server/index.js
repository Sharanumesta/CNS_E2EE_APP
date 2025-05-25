import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import bodyParser from "body-parser";
import cors from "cors";
import userRoutes from "./routes/user.routes.js";
import facultyRoutes from "./routes/faculty.routes.js";
import studentRouter from "./routes/student.routes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT;

// Middleware
app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

// Database connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// Routes
app.use("/api/users", userRoutes);
app.use("/api/faculty", facultyRoutes);
app.use("/api/student", studentRouter);


app.listen(PORT, "0.0.0.0", () => {
  console.log("Server is running on port 8080");
});
