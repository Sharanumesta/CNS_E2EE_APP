import React, { useState, useEffect } from "react";
import { View, Alert } from "react-native";
import {
  TextInput,
  Button,
  Text,
  ActivityIndicator,
  RadioButton,
} from "react-native-paper";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import Constants from "expo-constants";
import forge from "node-forge";

const { API_URL } = Constants.expoConfig.extra;

const LoginScreen = ({ navigation }) => {
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("student");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setIdentifier("");
  }, [role]);

  const handleLogin = async () => {
    if (!identifier || !password) {
      Alert.alert("Error", "Please enter both identifier and password.");
      return;
    }

    setLoading(true);

    try {
      const response = await axios.post(`${API_URL}/users/login`, {
        identifier,
        password,
        role,
      });

      const { token, encryptedPrivateKey, iv, salt, user } = response.data;

      if (!encryptedPrivateKey || typeof encryptedPrivateKey !== "string") {
        Alert.alert("Error", "Encrypted private key is missing or invalid.");
        setLoading(false);
        return;
      }

      if (!iv || !salt) {
        Alert.alert("Error", "Encryption parameters are missing.");
        setLoading(false);
        return;
      }

      if (!["student", "faculty"].includes(user.role)) {
        Alert.alert("Error", "Only student and faculty roles are allowed.");
        setLoading(false);
        return;
      }

      // Save securely for use in StudentScreen or FacultyScreen
      // Save token, encrypted key, etc.
      await SecureStore.setItemAsync("token", token);
      await SecureStore.setItemAsync(
        "encryptedPrivateKey",
        encryptedPrivateKey
      );
      await SecureStore.setItemAsync("iv", iv);
      await SecureStore.setItemAsync("salt", salt);

      // Save studentId or userId to SecureStore
      await SecureStore.setItemAsync("studentId", user._id || user.id); // use the correct field name here

      Alert.alert("Success", `Logged in as ${user.role}`);

      // Navigate to the correct screen
      if (user.role === "faculty") {
        navigation.replace("FacultyScreen");
      } else if (user.role === "student") {
        navigation.replace("StudentScreen");
      }
    } catch (error) {
      console.error("Login error:", error?.response?.data || error.message);
      Alert.alert(
        "Login Failed",
        error?.response?.data?.error || "Invalid credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <View
      style={{
        flex: 1,
        backgroundColor: "#FFFFFF",
        padding: 20,
        justifyContent: "center",
      }}
    >
      <Text
        variant="titleLarge"
        style={{
          textAlign: "center",
          marginBottom: 20,
          color: "#1E90FF",
          fontWeight: "bold",
          textTransform: "uppercase",
        }}
      >
        Login
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
        style={{ marginBottom: 16 }}
      />

      {loading ? (
        <ActivityIndicator animating={true} size="large" />
      ) : (
        <>
          <Button
            mode="contained"
            onPress={handleLogin}
            style={{
              marginTop: 10,
              borderRadius: 5,
              backgroundColor: "#1E90FF",
            }}
          >
            Login
          </Button>

          <Button
            mode="text"
            onPress={() => navigation.navigate("Register")}
            style={{ marginTop: 10 }}
            textColor="#1E90FF"
          >
            Don't have an account? Register
          </Button>
        </>
      )}
    </View>
  );
};

export default LoginScreen;
