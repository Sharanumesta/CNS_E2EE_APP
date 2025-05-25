import mongoose from 'mongoose';

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  encryptedContent: { type: String, required: true },
  iv: { type: String, required: true },
  encryptedKey: { type: String, required: true },
  messageType: { type: String, enum: ["result", "placement", "update"], required: true },
  createdAt: { type: Date, default: Date.now },
});

// Export as default model
const Message = mongoose.model('Message', messageSchema);

export default Message;
