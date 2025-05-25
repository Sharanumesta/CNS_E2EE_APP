import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  role: { type: String, enum: ["faculty", "student"], required: true },
  // For students, we have USN
  usn: { type: String, unique: true, sparse: true },
  // For faculty, use employeeId (or any other unique id)
  employeeId: { type: String, unique: true, sparse: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true },
  encryptedPrivateKey: { type: String, required: true },
  iv: { type: String, required: true },       // add this
  salt: { type: String, required: true },     // add this
  department: String,
  phoneNumber: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

export default User;
