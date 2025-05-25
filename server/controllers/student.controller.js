import mongoose from "mongoose";
import MessageModel from "../models/message.model.js";

export const fetchMessages = async (req, res) => {
  try {
    const studentId = req.user.id;

    // Use 'new' when creating ObjectId
    const studentObjectId = new mongoose.Types.ObjectId(studentId);

    const messages = await MessageModel.find({
      receiver: studentObjectId,
    }).lean();

    return res.json({ messages });
  } catch (error) {
    console.error("[fetchMessages] Error:", error);
    return res.status(500).json({ message: "Failed to fetch messages" });
  }
};
