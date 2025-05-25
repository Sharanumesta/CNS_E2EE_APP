import React, { useState, useEffect } from "react";
import { View, FlatList, StyleSheet, KeyboardAvoidingView } from "react-native";
import { TextInput, Button, Text, Title } from "react-native-paper";
import axios from "axios";
import * as SecureStore from "expo-secure-store";
import { decryptMessage } from "../utils/crypto";

const MessageScreen = ({ route }) => {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const { contact } = route.params;

  useEffect(() => {
    fetchMessages();
  }, []);

  const fetchMessages = async () => {
    const token = await SecureStore.getItemAsync("token");
    const response = await axios.get(`http://YOUR_SERVER_IP:5000/api/messages/${contact._id}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    const privateKey = await SecureStore.getItemAsync("privateKey");
    const decryptedMessages = response.data.map((msg) => ({
      ...msg,
      content: decryptMessage(msg, privateKey),
    }));

    setMessages(decryptedMessages);
  };

  const sendMessage = async () => {
    const token = await SecureStore.getItemAsync("token");
    await axios.post(
      "http://YOUR_SERVER_IP:5000/api/messages",
      {
        receiver: contact._id,
        message,
        messageType: "update",
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    setMessage("");
    fetchMessages();
  };

  return (
    <KeyboardAvoidingView style={styles.container} behavior="padding">
      <Title style={styles.title}>Chat with {contact.username}</Title>
      <FlatList
        data={messages}
        keyExtractor={(item) => item._id}
        renderItem={({ item }) => (
          <View style={styles.messageBubble}>
            <Text>{item.content}</Text>
          </View>
        )}
        contentContainerStyle={styles.messageList}
      />
      <TextInput
        value={message}
        onChangeText={setMessage}
        placeholder="Type your secure message"
        style={styles.input}
        mode="outlined"
      />
      <Button mode="contained" onPress={sendMessage} style={styles.button}>
        Send
      </Button>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#FFFFFF",
    padding: 20,
  },
  title: {
    fontSize: 20,
    color: "#1E90FF",
    marginBottom: 10,
    fontWeight: "bold",
    textAlign: "center",
  },
  messageList: {
    flexGrow: 1,
    marginBottom: 20,
  },
  messageBubble: {
    backgroundColor: "#F0F8FF",
    padding: 10,
    borderRadius: 6,
    marginVertical: 4,
  },
  input: {
    marginBottom: 10,
    backgroundColor: "#F0F8FF",
  },
  button: {
    backgroundColor: "#1E90FF",
  },
});

export default MessageScreen;
