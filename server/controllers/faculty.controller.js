import User from "../models/user.model.js";
import Message from "../models/message.model.js";

// Fetch students assigned to the logged-in faculty
export const getAssignedStudents = async (req, res) => {
  try {
    if (!req.user || req.user.role !== "faculty") {
      return res.status(403).json({ message: "Access denied" });
    }

    // Fetch all students, no filter on assignedFaculty
    const students = await User.find({ role: "student" }).select(
      "_id publicKey"
    );

    if (!students.length) {
      return res.status(404).json({ message: "No students found" });
    }

    return res.status(200).json({ students });
  } catch (error) {
    console.error("Error fetching students:", error);
    return res.status(500).json({ message: "Server error" });
  }
};

// Send encrypted messages to assigned students only
export const sendEncryptedMessages = async (req, res) => {
  try {
    if (!req.user || req.user.role !== "faculty") {
      return res.status(403).json({ message: "Access denied" });
    }
    
    const { messageType, encryptedContent, iv, encryptedKey } = req.body;
    console.log("Encrypted message:", encryptedContent);

    if (!messageType || !encryptedContent || !iv || !encryptedKey) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    const students = await User.find({ role: "student" });

    if (students.length === 0) {
      return res.status(404).json({ message: "No students found" });
    }

    const savePromises = students
      .map((student) => {
        const studentEncryptedKey = encryptedKey[student._id.toString()];
        if (!studentEncryptedKey) return null;

        const newMessage = new Message({
          sender: req.user.id,
          receiver: student._id,
          messageType,
          encryptedContent,
          iv,
          encryptedKey: studentEncryptedKey,
          createdAt: new Date(),
        });

        return newMessage.save();
      })
      .filter(Boolean);

    await Promise.all(savePromises);

    return res
      .status(200)
      .json({ message: "Encrypted messages sent to all students" });
  } catch (error) {
    console.error("Error sending encrypted messages:", error);
    return res.status(500).json({ message: "Server error" });
  }
};
