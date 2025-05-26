import forge from "node-forge";

// === RSA Key Pair Generation ===
export const generateKeyPair = async () => {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair(
      { bits: 2048, workers: -1 },
      (err, keypair) => {
        if (err) {
          console.error("[generateKeyPair] Error:", err);
          reject(err);
          return;
        }
        const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
        const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

        // Validate the key pair works
        const testMsg = "test message";
        const encrypted = keypair.publicKey.encrypt(testMsg, "RSA-OAEP", {
          md: forge.md.sha256.create(),
          mgf1: { md: forge.md.sha256.create() },
        });
        const decrypted = keypair.privateKey.decrypt(encrypted, "RSA-OAEP", {
          md: forge.md.sha256.create(),
          mgf1: { md: forge.md.sha256.create() },
        });

        if (decrypted !== testMsg) {
          reject(new Error("Generated key pair validation failed"));
          return;
        }

        resolve({
          publicKey: publicKeyPem,
          privateKey: privateKeyPem,
        });
      }
    );
  });
};

// === Encrypt Private Key with AES-CBC + PBKDF2 ===
export const encryptPrivateKey = async (privateKeyPem, password) => {
  const salt = forge.random.getBytesSync(16);
  const iv = forge.random.getBytesSync(16);

  // Key derivation with PBKDF2
  const key = forge.pkcs5.pbkdf2(
    password,
    salt,
    10000, // iterations
    32, // key size (32 bytes = 256 bits)
    forge.md.sha256.create()
  );

  // AES-CBC encryption
  const cipher = forge.cipher.createCipher("AES-CBC", key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(privateKeyPem, "utf8"));
  cipher.finish();

  return {
    cipherText: forge.util.encode64(cipher.output.getBytes()),
    iv: forge.util.encode64(iv),
    salt: forge.util.encode64(salt),
  };
};

// === Decrypt Private Key with AES-CBC + PBKDF2 ===
export const decryptPrivateKey = (encryptedPem, password, saltB64, ivB64) => {
  try {
    // Decode base64 parameters
    const salt = forge.util.decode64(saltB64);
    const iv = forge.util.decode64(ivB64);
    const encryptedBytes = forge.util.decode64(encryptedPem);

    // Recreate the key
    const key = forge.pkcs5.pbkdf2(
      password,
      salt,
      10000,
      32,
      forge.md.sha256.create()
    );

    // Decrypt
    const decipher = forge.cipher.createDecipher("AES-CBC", key);
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(encryptedBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error("Decryption failed - possibly wrong password");
    }

    const decrypted = decipher.output.toString();

    // Validate the decrypted private key
    forge.pki.privateKeyFromPem(decrypted);
    return decrypted;
  } catch (err) {
    console.error("[decryptPrivateKey] Error:", {
      message: err.message,
      saltLength: saltB64?.length,
      ivLength: ivB64?.length,
      encryptedLength: encryptedPem?.length,
    });
    throw new Error("Failed to decrypt private key");
  }
};

// === Encrypt Message for Students (Hybrid RSA-AES) ===
export const encryptMessageForStudents = async (plainText, students) => {
  try {
    if (!plainText || typeof plainText !== "string") {
      throw new Error("Message must be a non-empty string");
    }

    // Generate random AES key and IV
    const aesKey = forge.random.getBytesSync(32);
    const iv = forge.random.getBytesSync(16);

    // Encrypt message with AES
    const cipher = forge.cipher.createCipher("AES-CBC", aesKey);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plainText, "utf8"));
    cipher.finish();
    const encryptedContent = forge.util.encode64(cipher.output.getBytes());

    // Encrypt AES key for each student
    const encryptedKeys = {};
    for (const student of students) {
      try {
        const publicKey = forge.pki.publicKeyFromPem(student.publicKey);

        const encryptedAesKey = publicKey.encrypt(aesKey, "RSA-OAEP", {
          md: forge.md.sha256.create(),
          mgf1: { md: forge.md.sha256.create() },
        });

        encryptedKeys[student._id] = forge.util.encode64(encryptedAesKey);
      } catch (e) {
        console.error(`Failed to encrypt for student ${student._id}:`, e);
        throw e;
      }
    }

    return {
      encryptedContent,
      iv: forge.util.encode64(iv),
      encryptedKey: encryptedKeys,
    };
  } catch (error) {
    console.error("[encryptMessageForStudents] Error:", error);
    throw error;
  }
};

export const decryptMessage = (message, privateKeyPem, currentStudentId) => {
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
        throw new Error(`No encrypted key found for student ID: ${currentStudentId}`);
      }
    } else {
      throw new Error("Invalid encryptedKey format");
    }

    const encryptedKeyBytes = forge.util.decode64(encryptedAesKey);

    const aesKey = privateKey.decrypt(encryptedKeyBytes, "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: {
        md: forge.md.sha256.create(),
      },
    });

    const ivBytes = forge.util.decode64(message.iv);
    const encryptedContentBytes = forge.util.decode64(message.encryptedContent);

    const decipher = forge.cipher.createDecipher("AES-CBC", aesKey);
    decipher.start({ iv: ivBytes });
    decipher.update(forge.util.createBuffer(encryptedContentBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error("AES decryption failed");
    }

    return decipher.output.toString();
  } catch (err) {
    console.error("[DecryptMessage] Error decrypting message:", err);
    return "[Decryption failed: " + err.message + "]";
  }
};

// import * as SecureStore from 'expo-secure-store';
// import forge from 'node-forge';

// const AES_KEY_SIZE = 32; // 256-bit key
// const IV_SIZE = 16;      // 128-bit IV

// // === Generate and store AES key securely per student ===
// export const generateAndStoreSymmetricKey = async (studentId) => {
//   try {
//     const key = forge.random.getBytesSync(AES_KEY_SIZE);
//     const encodedKey = forge.util.encode64(key);
//     await SecureStore.setItemAsync(`aesKey-${studentId}`, encodedKey);
//     return encodedKey;
//   } catch (error) {
//     console.error('[generateAndStoreSymmetricKey] Error:', error);
//     throw new Error('Failed to generate or store AES key');
//   }
// };

// // === Retrieve AES key from SecureStore ===
// export const getSymmetricKey = async (studentId) => {
//   try {
//     const stored = await SecureStore.getItemAsync(`aesKey-${studentId}`);
//     if (!stored) throw new Error('Missing AES key for student');
//     return stored;
//   } catch (error) {
//     console.error('[getSymmetricKey] Error:', error);
//     throw error;
//   }
// };

// // === Encrypt plain text using AES-CBC ===
// export const encryptMessage = (plainText, aesKeyBase64) => {
//   if (typeof plainText !== "string") {
//     throw new Error("plainText must be a string");
//   }
//   if (typeof aesKeyBase64 !== "string") {
//     throw new Error("aesKeyBase64 must be a string");
//   }

//   const aesKey = forge.util.decode64(aesKeyBase64);
//   const iv = forge.random.getBytesSync(IV_SIZE);

//   const cipher = forge.cipher.createCipher("AES-CBC", aesKey);
//   cipher.start({ iv });
//   cipher.update(forge.util.createBuffer(plainText, "utf8"));
//   cipher.finish();

//   return {
//     encryptedContent: forge.util.encode64(cipher.output.getBytes()),
//     iv: forge.util.encode64(iv),
//   };
// };




// // === Decrypt encrypted content using AES-CBC ===
// export const decryptMessage = async (message, studentId) => {
//   try {
//     const aesKeyBase64 = await getSymmetricKey(studentId);
//     const aesKey = forge.util.decode64(aesKeyBase64);
//     const ivBytes = forge.util.decode64(message.iv);
//     const encryptedBytes = forge.util.decode64(message.encryptedContent);

//     const decipher = forge.cipher.createDecipher('AES-CBC', aesKey);
//     decipher.start({ iv: ivBytes });
//     decipher.update(forge.util.createBuffer(encryptedBytes));
//     const success = decipher.finish();

//     if (!success) throw new Error('AES decryption failed');
//     return decipher.output.toString();
//   } catch (error) {
//     console.error('[decryptMessage] Error:', error);
//     return `[Decryption failed: ${error.message}]`;
//   }
// };
