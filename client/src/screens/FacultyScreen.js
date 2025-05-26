import React, { useState, useEffect } from "react";
import { View, Alert, ScrollView } from "react-native";
import { TextInput, Button, Text, ActivityIndicator } from "react-native-paper";
import axios from "axios";
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";
import { encryptMessageForStudents } from "../utils/crypto.js";

const { API_URL } = Constants.expoConfig.extra;

const messageOptions = [
  { label: "Results", value: "result" },
  { label: "Placement", value: "placement" },
  { label: "Department's Updates", value: "update" },
];

const FacultySendMessage = () => {
  const [messageType, setMessageType] = useState("result");
  const [message, setMessage] = useState("");
  const [students, setStudents] = useState([]); // [{ _id, publicKey }]
  const [loading, setLoading] = useState(false);
  const [token, setToken] = useState("");

  useEffect(() => {
    (async () => {
      const storedToken = await SecureStore.getItemAsync("token");
      if (!storedToken) {
        Alert.alert("Error", "No authentication token found, please login again.");
        return;
      }
      setToken(storedToken);
    })();
  }, []);

  useEffect(() => {
    if (!token) return;
    (async () => {
      try {
        const res = await axios.get(`${API_URL}/faculty/students`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        setStudents(res.data.students);
      } catch (err) {
        Alert.alert("Error", err.response?.data?.message || "Failed to load students");
      }
    })();
  }, [token]);

  const handleSend = async () => {
    if (!message.trim()) {
      Alert.alert("Validation", "Please enter a message");
      return;
    }
    if (!["result", "placement", "update"].includes(messageType)) {
      Alert.alert("Validation", "Invalid message type");
      return;
    }
    if (students.length === 0) {
      Alert.alert("Error", "No students to send message to");
      return;
    }

    setLoading(true);
    try {
      // Call your imported crypto function directly
      const { encryptedContent, iv, encryptedKey } = await encryptMessageForStudents(message, students);

      const payload = {
        messageType,
        encryptedContent,
        iv,
        encryptedKey,
      };

      await axios.post(`${API_URL}/faculty/messages`, payload, {
        headers: { Authorization: `Bearer ${token}` },
      });

      Alert.alert("Success", "Encrypted message sent successfully");
      setMessage("");
    } catch (err) {
      Alert.alert("Error", err.message || "Failed to send encrypted message");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ScrollView contentContainerStyle={{ padding: 20 }}>
      <Text variant="titleLarge" style={{ marginBottom: 20, textAlign: "center" }}>
        Faculty - Send E2E Encrypted Message
      </Text>

      <Text style={{ marginBottom: 8 }}>Message Type</Text>
      <View style={{ marginBottom: 16, flexDirection: "row", justifyContent: "space-around" }}>
        {messageOptions.map((opt) => (
          <Button
            key={opt.value}
            mode={messageType === opt.value ? "contained" : "outlined"}
            onPress={() => setMessageType(opt.value)}
            style={{ flex: 1, marginHorizontal: 4 }}
          >
            {opt.label}
          </Button>
        ))}
      </View>

      <TextInput
        label="Message Content"
        value={message}
        onChangeText={setMessage}
        mode="outlined"
        multiline
        numberOfLines={5}
        style={{ marginBottom: 16, height: 120 }}
      />

      {loading ? (
        <ActivityIndicator animating size="large" />
      ) : (
        <Button mode="contained" onPress={handleSend}>
          Send Encrypted Message
        </Button>
      )}

      <Text style={{ marginTop: 16, fontSize: 12, color: "gray", textAlign: "center" }}>
        Messages are encrypted with AES-256 + RSA-OAEP for end-to-end security
      </Text>
    </ScrollView>
  );
};

export default FacultySendMessage;
