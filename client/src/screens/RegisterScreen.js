import React, { useState } from "react";
import { View, Alert } from "react-native";
import {
  TextInput,
  Button,
  Text,
  ActivityIndicator,
  RadioButton,
} from "react-native-paper";
import axios from "axios";
import { generateKeyPair, encryptPrivateKey } from "../utils/crypto.js";
import Constants from "expo-constants";

const { API_URL } = Constants.expoConfig.extra;

const RegisterScreen = ({ navigation }) => {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [role, setRole] = useState("student");
  const [department, setDepartment] = useState("");
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    if (!identifier.trim())
      return Alert.alert(
        "Error",
        role === "student" ? "USN is required." : "Faculty ID is required."
      );
    if (!password || password.length < 8)
      return Alert.alert("Error", "Password must be at least 8 characters.");
    if (!/[A-Z]/.test(password) || !/[0-9]/.test(password))
      return Alert.alert(
        "Error",
        "Password must include uppercase and number."
      );
    if (password !== confirmPassword)
      return Alert.alert("Error", "Passwords do not match.");
    if (!/^[0-9]{10}$/.test(phoneNumber))
      return Alert.alert("Error", "Phone number must be 10 digits.");
    if (!["student", "faculty"].includes(role.toLowerCase()))
      return Alert.alert("Error", "Role must be student or faculty.");

    setLoading(true);

    try {
      const { publicKey, privateKey } = await generateKeyPair();
      const { cipherText, iv, salt } = await encryptPrivateKey(
        privateKey,
        password
      );

      // Prepare payload with correct key for identifier
      const payload = {
        role,
        password,
        phoneNumber,
        department,
        publicKey,
        encryptedPrivateKey: cipherText,
        iv,
        salt,
      };

      // Add identifier as usn or employeeId depending on role
      if (role === "student") {
        payload.usn = identifier;
      } else if (role === "faculty") {
        payload.employeeId = identifier;
      }

      await axios.post(`${API_URL}/users/register`, payload);

      Alert.alert("Success", "Registration successful! Please log in.");
      navigation.navigate("Login");
    } catch (error) {
      console.error("Registration error:", error);
      let message = "Registration failed. Try again.";
      if (error.response?.data?.error) {
        message = error.response.data.error;
      }
      Alert.alert("Error", message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={{ flex: 1, padding: 20, justifyContent: "center" }}>
      <Text
        variant="titleLarge"
        style={{ textAlign: "center", marginBottom: 20 }}
      >
        Register
      </Text>
      <Text style={{ marginBottom: 8 }}>Select Role</Text>
      <RadioButton.Group onValueChange={setRole} value={role}>
        <View style={{ flexDirection: "row", marginBottom: 12 }}>
          <RadioButton.Item label="Student" value="student" />
          <RadioButton.Item label="Faculty" value="faculty" />
        </View>
      </RadioButton.Group>

      <TextInput
        label={role === "student" ? "USN" : "Faculty ID"}
        value={identifier}
        onChangeText={setIdentifier}
        autoCapitalize="none"
        mode="outlined"
        style={{ marginBottom: 12 }}
      />

      <TextInput
        label="Password"
        value={password}
        onChangeText={setPassword}
        secureTextEntry
        mode="outlined"
        style={{ marginBottom: 12 }}
      />

      <TextInput
        label="Confirm Password"
        value={confirmPassword}
        onChangeText={setConfirmPassword}
        secureTextEntry
        mode="outlined"
        style={{ marginBottom: 12 }}
      />

      <TextInput
        label="Phone Number"
        value={phoneNumber}
        onChangeText={setPhoneNumber}
        keyboardType="phone-pad"
        mode="outlined"
        style={{ marginBottom: 12 }}
      />

      <TextInput
        label="Department (optional)"
        value={department}
        onChangeText={setDepartment}
        mode="outlined"
        style={{ marginBottom: 12 }}
      />

      {loading ? (
        <ActivityIndicator animating={true} size="large" />
      ) : (
        <>
          <Button
            mode="contained"
            onPress={handleRegister}
            style={{ marginBottom: 10 }}
          >
            Register
          </Button>
          <Button
            mode="text"
            onPress={() => navigation.navigate("Login")}
            textColor="#1E90FF"
          >
            Already registered? Login
          </Button>
        </>
      )}
    </View>
  );
};

export default RegisterScreen;
