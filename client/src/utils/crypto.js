import forge from "node-forge";

/**
 * === RSA Key Pair Generation ===
 * Generates a 2048-bit RSA key pair (public/private).
 * Validates the key by encrypting and decrypting a test message.
 */
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

        // Validate key pair by performing encrypt/decrypt
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

/**
 * === Encrypt Private Key (AES-CBC + PBKDF2) ===
 * Secures the private key using a password-based AES encryption.
 * PBKDF2 derives a strong key from the password.
 */
export const encryptPrivateKey = async (privateKeyPem, password) => {
  const salt = forge.random.getBytesSync(16);
  const iv = forge.random.getBytesSync(16);

  // Derive AES key from password
  const key = forge.pkcs5.pbkdf2(password, salt, 10000, 32, forge.md.sha256.create());

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

/**
 * === Decrypt Private Key (AES-CBC + PBKDF2) ===
 * Reverses the encryption above using the same password and parameters.
 * Throws error if decryption fails or password is incorrect.
 */
export const decryptPrivateKey = (encryptedPem, password, saltB64, ivB64) => {
  try {
    const salt = forge.util.decode64(saltB64);
    const iv = forge.util.decode64(ivB64);
    const encryptedBytes = forge.util.decode64(encryptedPem);

    const key = forge.pkcs5.pbkdf2(password, salt, 10000, 32, forge.md.sha256.create());

    const decipher = forge.cipher.createDecipher("AES-CBC", key);
    decipher.start({ iv });
    decipher.update(forge.util.createBuffer(encryptedBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error("Decryption failed - possibly wrong password");
    }

    const decrypted = decipher.output.toString();

    // Parse PEM format to ensure it's valid
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

/**
 * === Encrypt Message for Students (Hybrid Encryption) ===
 * Uses AES-CBC to encrypt the message content.
 * Then encrypts the AES key using each student's RSA public key.
 * Result: one encrypted message + encrypted keys for each student.
 */
export const encryptMessageForStudents = async (plainText, students) => {
  try {
    if (!plainText || typeof plainText !== "string") {
      throw new Error("Message must be a non-empty string");
    }

    // Generate AES key and IV
    const aesKey = forge.random.getBytesSync(32);
    const iv = forge.random.getBytesSync(16);

    // Encrypt the message using AES
    const cipher = forge.cipher.createCipher("AES-CBC", aesKey);
    cipher.start({ iv });
    cipher.update(forge.util.createBuffer(plainText, "utf8"));
    cipher.finish();
    const encryptedContent = forge.util.encode64(cipher.output.getBytes());

    // Encrypt the AES key with each student's RSA public key
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

/**
 * === Decrypt Message ===
 * Student uses their RSA private key to decrypt the AES key.
 * Then decrypts the AES-encrypted content using that key and IV.
 */
export const decryptMessage = (message, privateKeyPem, currentStudentId) => {
  try {
    if (!message.encryptedKey || !message.iv || !message.encryptedContent) {
      throw new Error("Missing encryption fields");
    }

    const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

    // Determine the AES key specific to this student
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

    // Decrypt AES key using RSA private key
    const aesKey = privateKey.decrypt(encryptedKeyBytes, "RSA-OAEP", {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() },
    });

    // Use decrypted AES key to decrypt message
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
