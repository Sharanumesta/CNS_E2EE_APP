import React, { useEffect, useState } from "react";
import {
  View,
  FlatList,
  Alert,
  KeyboardAvoidingView,
  Platform,
  TextInput as RNTextInput,
} from "react-native";
import {
  Text,
  Card,
  ActivityIndicator,
  Button,
  Dialog,
  Portal,
} from "react-native-paper";
import axios from "axios";
import forge from "node-forge";
import * as SecureStore from "expo-secure-store";
import Constants from "expo-constants";
import { decryptMessage, decryptPrivateKey } from "../utils/crypto";

const { API_URL } = Constants.expoConfig.extra;

const MAX_CHUNK_SIZE = 2000;

const storePrivateKeySafely = async (key, value) => {
  if (value.length <= MAX_CHUNK_SIZE) {
    await SecureStore.setItemAsync(key, value);
    await SecureStore.deleteItemAsync(`${key}_chunks`).catch(() => {});
  } else {
    const chunks = [];
    for (let i = 0; i < value.length; i += MAX_CHUNK_SIZE) {
      chunks.push(value.substring(i, i + MAX_CHUNK_SIZE));
    }
    await SecureStore.setItemAsync(`${key}_chunks`, chunks.length.toString());
    await Promise.all(
      chunks.map((chunk, i) => SecureStore.setItemAsync(`${key}_${i}`, chunk))
    );
    await SecureStore.deleteItemAsync(key).catch(() => {});
  }
};

const loadPrivateKeySafely = async (key) => {
  try {
    const singleValue = await SecureStore.getItemAsync(key);
    if (singleValue) return singleValue;

    const chunksCountStr = await SecureStore.getItemAsync(`${key}_chunks`);
    if (!chunksCountStr) return null;

    const chunksCount = parseInt(chunksCountStr);
    const chunks = await Promise.all(
      Array.from({ length: chunksCount }, (_, i) =>
        SecureStore.getItemAsync(`${key}_${i}`)
      )
    );

    if (chunks.includes(null))
      throw new Error("One or more key chunks are missing");

    return chunks.join("");
  } catch (error) {
    console.error("[loadPrivateKeySafely] Error:", error);
    return null;
  }
};

const StudentScreen = () => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [password, setPassword] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [passwordDialogVisible, setPasswordDialogVisible] = useState(false);
  const [token, setToken] = useState(null);
  const [studentId, setStudentId] = useState(null);

  useEffect(() => {
    const initialize = async () => {
      try {
        const storedToken = await SecureStore.getItemAsync("token");
        const storedStudentId = await SecureStore.getItemAsync("studentId");

        if (!storedToken || !storedStudentId) {
          Alert.alert(
            "Error",
            "No token or student ID found, please login again."
          );
          return;
        }

        setToken(storedToken);
        setStudentId(storedStudentId);

        const storedKey = await loadPrivateKeySafely("privateKeyPem");
        if (storedKey) {
          setPrivateKeyPem(storedKey);
          await fetchMessagesAndDecrypt(storedKey, storedToken);
        } else {
          setPasswordDialogVisible(true);
        }
      } catch (err) {
        console.error("[Init] Error:", err);
        Alert.alert("Error", "Failed to initialize student screen.");
      }
    };

    initialize();
  }, []);

  const onRefresh = async () => {
    if (!privateKeyPem || !token) {
      Alert.alert("Error", "You must be logged in to refresh messages.");
      return;
    }

    setRefreshing(true);
    try {
      await fetchMessagesAndDecrypt(privateKeyPem, token);
    } catch (error) {
      console.error("[onRefresh] Error:", error);
      Alert.alert("Error", "Failed to refresh messages.");
    } finally {
      setRefreshing(false);
    }
  };

  const loadEncryptedPrivateKey = async () => {
    try {
      const encryptedKey = await SecureStore.getItemAsync(
        "encryptedPrivateKey"
      );
      if (!encryptedKey) throw new Error("Encrypted private key not found");
      return encryptedKey;
    } catch (err) {
      console.error("[loadEncryptedPrivateKey] Error:", err);
      Alert.alert("Error", "Failed to load encrypted private key.");
      return null;
    }
  };

  const fetchMessagesAndDecrypt = async (keyPem, authToken) => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_URL}/student/messages`, {
        headers: { Authorization: `Bearer ${authToken}` },
      });

      const decryptedMessages = res.data.messages.map((msg) => ({
        ...msg,
        decryptedContent: decryptMessage(msg, keyPem, studentId),
      }));

      setMessages(decryptedMessages);
      setPasswordDialogVisible(false);
    } catch (error) {
      console.error("[fetchMessagesAndDecrypt] Error:", error);
      Alert.alert("Error", "Failed to fetch or decrypt messages.");
    } finally {
      setLoading(false);
    }
  };

  const onPasswordSubmit = async () => {
    if (!password) {
      Alert.alert("Error", "Please enter your password.");
      return;
    }

    setLoading(true);
    try {
      const encryptedPem = await loadEncryptedPrivateKey();
      const salt = await SecureStore.getItemAsync("salt");
      const iv = await SecureStore.getItemAsync("iv");

      if (!encryptedPem || !salt || !iv) {
        throw new Error("Missing encrypted key, salt, or IV.");
      }

      const decryptedKey = decryptPrivateKey(encryptedPem, password, salt, iv);
      forge.pki.privateKeyFromPem(decryptedKey); // validate

      await storePrivateKeySafely("privateKeyPem", decryptedKey);
      await fetchMessagesAndDecrypt(decryptedKey, token);
      setPrivateKeyPem(decryptedKey);
    } catch (err) {
      console.error("[onPasswordSubmit] Error:", err);
      Alert.alert("Error", err.message || "Failed to decrypt key.");
    } finally {
      setLoading(false);
    }
  };

  const renderMessage = ({ item }) => (
    <Card style={{ marginVertical: 8, marginHorizontal: 12 }}>
      <Card.Title
        title={`Type: ${item.messageType}`}
        subtitle={`Sent: ${new Date(item.createdAt).toLocaleString()}`}
      />
      <Card.Content>
        <Text
          style={{
            fontSize: 16,
            lineHeight: 24,
            color: item.decryptedContent?.startsWith("[Decryption failed")
              ? "red"
              : "black",
          }}
        >
          {item.decryptedContent || "[Encrypted content]"}
        </Text>
      </Card.Content>
    </Card>
  );

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
        <ActivityIndicator animating size="large" />
        <Text style={{ marginTop: 16 }}>
          {passwordDialogVisible ? "Decrypting messages..." : "Loading..."}
        </Text>
      </View>
    );
  }

  return (
    <KeyboardAvoidingView
      style={{ flex: 1 }}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <FlatList
        data={messages}
        keyExtractor={(item) => item._id}
        renderItem={renderMessage}
        contentContainerStyle={{ padding: 10 }}
        ListEmptyComponent={
          <View style={{ marginTop: 50, alignItems: "center" }}>
            <Text style={{ color: "gray", fontSize: 16 }}>
              No messages found.
            </Text>
          </View>
        }
        refreshing={refreshing}
        onRefresh={onRefresh}
      />

      <Portal>
        <Dialog visible={passwordDialogVisible} dismissable={false}>
          <Dialog.Title>Decrypt Messages</Dialog.Title>
          <Dialog.Content>
            <Text style={{ marginBottom: 10, color: "gray" }}>
              Enter your password to unlock your private key.
            </Text>
            <RNTextInput
              placeholder="Password"
              secureTextEntry
              value={password}
              onChangeText={setPassword}
              style={{
                backgroundColor: "white",
                padding: 10,
                borderRadius: 4,
                borderWidth: 1,
                borderColor: "#ccc",
              }}
              onSubmitEditing={onPasswordSubmit}
              autoFocus
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={onPasswordSubmit} mode="contained">
              Decrypt
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
      <Text
        style={{
          marginTop: 16,
          fontSize: 16,
          color: "gray",
          textAlign: "center",
        }}
      >
        Messages are encrypted with AES-256 + RSA-OAEP for end-to-end security
      </Text>
    </KeyboardAvoidingView>
  );
};

export default StudentScreen;
