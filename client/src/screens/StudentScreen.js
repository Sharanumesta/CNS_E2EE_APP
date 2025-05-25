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
import { decryptPrivateKey } from "../utils/crypto.js";

const { API_URL } = Constants.expoConfig.extra;

const storePrivateKeySafely = async (key, value) => {
  const maxChunkSize = 2000;

  if (value.length <= maxChunkSize) {
    await SecureStore.setItemAsync(key, value);
    await SecureStore.deleteItemAsync(`${key}_chunks`).catch(() => {});
  } else {
    const chunks = [];
    for (let i = 0; i < value.length; i += maxChunkSize) {
      chunks.push(value.substring(i, i + maxChunkSize));
    }

    await SecureStore.setItemAsync(`${key}_chunks`, chunks.length.toString());

    for (let i = 0; i < chunks.length; i++) {
      await SecureStore.setItemAsync(`${key}_${i}`, chunks[i]);
    }

    await SecureStore.deleteItemAsync(key).catch(() => {});
  }
};

const loadPrivateKeySafely = async (key) => {
  try {
    const singleValue = await SecureStore.getItemAsync(key);
    if (singleValue) {
      return singleValue;
    }

    const chunksCountStr = await SecureStore.getItemAsync(`${key}_chunks`);
    if (!chunksCountStr) {
      return null;
    }

    const chunksCount = parseInt(chunksCountStr);
    const chunks = [];

    for (let i = 0; i < chunksCount; i++) {
      const chunk = await SecureStore.getItemAsync(`${key}_${i}`);
      if (!chunk) {
        throw new Error(`Missing chunk ${i} for key ${key}`);
      }
      chunks.push(chunk);
    }

    return chunks.join("");
  } catch (error) {
    console.error(`Error loading private key safely:`, error);
    return null;
  }
};

const StudentScreen = () => {
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [password, setPassword] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState(null); // <-- THIS WAS MISSING
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

        const storedDecryptedKey = await loadPrivateKeySafely("privateKeyPem");
        if (storedDecryptedKey) {
          setPrivateKeyPem(storedDecryptedKey);
          await fetchMessagesAndDecrypt(storedDecryptedKey, storedToken);
        } else {
          setPasswordDialogVisible(true);
        }
      } catch (err) {
        console.error("[Init] Error during initialization:", err);
        Alert.alert("Error", "Failed to initialize student screen");
      }
    };

    initialize();
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    try {
      if (!privateKeyPem || !token) {
        Alert.alert("Error", "You must be logged in to refresh messages.");
        setRefreshing(false);
        return;
      }
      await fetchMessagesAndDecrypt(privateKeyPem, token);
    } catch (error) {
      console.error("[Refresh] Error refreshing messages:", error);
      Alert.alert("Error", "Failed to refresh messages");
    } finally {
      setRefreshing(false);
    }
  };

  const loadEncryptedPrivateKey = async () => {
    try {
      const encryptedPrivateKeyPem = await SecureStore.getItemAsync(
        "encryptedPrivateKey"
      );
      if (!encryptedPrivateKeyPem) {
        throw new Error("Private key not found in storage");
      }
      return encryptedPrivateKeyPem;
    } catch (err) {
      console.error(
        "[LoadEncryptedKey] Error loading encrypted private key:",
        err
      );
      Alert.alert("Error", "Unable to load encrypted private key");
      return null;
    }
  };

  const decryptMessage = (message, privateKeyPem, currentStudentId) => {
    try {
      if (!message.encryptedKey || !message.iv || !message.encryptedContent) {
        throw new Error("Missing encryption fields");
      }

      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      let encryptedAesKey;
      if (typeof message.encryptedKey === "string") {
        encryptedAesKey = message.encryptedKey;
      } else if (typeof message.encryptedKey === "object") {
        encryptedAesKey = message.encryptedKey[currentStudentId];
        if (!encryptedAesKey) {
          throw new Error(
            `No encrypted key found for student ID: ${currentStudentId}`
          );
        }
      } else {
        throw new Error("Invalid encryptedKey format");
      }

      const encryptedKeyBytes = forge.util.decode64(encryptedAesKey);
      const aesKeyString = privateKey.decrypt(encryptedKeyBytes, "RSA-OAEP");

      const ivString = forge.util.decode64(message.iv);
      const encryptedContentBytes = forge.util.decode64(
        message.encryptedContent
      );

      const decipher = forge.cipher.createDecipher("AES-CBC", aesKeyString);
      decipher.start({ iv: ivString });
      decipher.update(forge.util.createBuffer(encryptedContentBytes));
      const success = decipher.finish();

      if (!success) {
        throw new Error("AES decryption failed");
      }

      return decipher.output.toString();
    } catch (err) {
      console.error("[DecryptMessage] Decryption error for message:", err);
      return "[Decryption failed: " + err.message + "]";
    }
  };

  const fetchMessagesAndDecrypt = async (
    decryptedPrivateKeyPem,
    accessToken
  ) => {
    setLoading(true);
    try {
      const tokenToUse = accessToken || token;

      const response = await axios.get(`${API_URL}/student/messages`, {
        headers: { Authorization: `Bearer ${tokenToUse}` },
      });

      const decryptedMessages = response.data.messages.map((msg) => ({
        ...msg,
        decryptedContent: decryptMessage(
          msg,
          decryptedPrivateKeyPem,
          studentId
        ),
      }));

      setMessages(decryptedMessages);
      setPrivateKeyPem(decryptedPrivateKeyPem);
      setPasswordDialogVisible(false);
    } catch (error) {
      console.error(
        "[FetchMessages] Error fetching or decrypting messages:",
        error
      );
      Alert.alert(
        "Error",
        "Failed to load or decrypt messages: " +
          (error.response?.data?.message || error.message)
      );
    } finally {
      setLoading(false);
    }
  };

  const onPasswordSubmit = async () => {
    if (!password) {
      Alert.alert("Error", "Please enter your password");
      return;
    }

    setLoading(true);
    try {
      const encryptedPrivateKeyPem = await loadEncryptedPrivateKey();
      if (!encryptedPrivateKeyPem) {
        setLoading(false);
        return;
      }

      const salt = await SecureStore.getItemAsync("salt");
      const iv = await SecureStore.getItemAsync("iv");

      if (!salt || !iv) {
        throw new Error("Missing salt or iv for decryption");
      }

      const decryptedPrivateKeyPem = decryptPrivateKey(
        encryptedPrivateKeyPem,
        password,
        salt,
        iv
      );

      forge.pki.privateKeyFromPem(decryptedPrivateKeyPem); // validate

      await storePrivateKeySafely("privateKeyPem", decryptedPrivateKeyPem);

      await fetchMessagesAndDecrypt(decryptedPrivateKeyPem);
    } catch (err) {
      console.error("[PasswordSubmit] Error:", err);
      Alert.alert("Error", err.message || "Failed to decrypt private key");
    } finally {
      setLoading(false);
    }
  };

  const renderMessage = ({ item }) => (
    <Card style={{ margin: 8 }}>
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
        <ActivityIndicator animating={true} size="large" />
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
          <View
            style={{
              flex: 1,
              justifyContent: "center",
              alignItems: "center",
              paddingTop: 50,
            }}
          >
            <Text style={{ textAlign: "center", fontSize: 16, color: "gray" }}>
              No messages found.
            </Text>
          </View>
        }
        refreshing={refreshing}
        onRefresh={onRefresh}
      />
      
      <Text
        style={{
          marginTop: 16,
          marginBottom: 16,
          fontSize: 12,
          color: "gray",
          textAlign: "center",
        }}
      >
        Messages are encrypted with AES-256 + RSA-OAEP for end-to-end security
      </Text>

      <Portal>
        <Dialog visible={passwordDialogVisible} dismissable={false}>
          <Dialog.Title>Enter Password to Decrypt Messages</Dialog.Title>
          <Dialog.Content>
            <Text style={{ marginBottom: 16, color: "gray" }}>
              Your password is required to decrypt your private key and view
              messages.
            </Text>
            <RNTextInput
              placeholder="Enter your password"
              secureTextEntry
              onChangeText={setPassword}
              value={password}
              style={{
                backgroundColor: "white",
                paddingHorizontal: 10,
                paddingVertical: 8,
                borderRadius: 4,
                borderWidth: 1,
                borderColor: "#ddd",
                marginTop: 10,
              }}
              autoFocus
              onSubmitEditing={onPasswordSubmit}
            />
          </Dialog.Content>
          <Dialog.Actions>
            <Button onPress={onPasswordSubmit} mode="contained">
              Decrypt Messages
            </Button>
          </Dialog.Actions>
        </Dialog>
      </Portal>
    </KeyboardAvoidingView>
  );
};

export default StudentScreen;
