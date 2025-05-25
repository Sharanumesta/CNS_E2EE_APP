import forge from 'node-forge';

// === RSA Key Pair Generation ===
export const generateKeyPair = async () => {
  return new Promise((resolve, reject) => {
    forge.pki.rsa.generateKeyPair({ bits: 2048, workers: -1 }, (err, keypair) => {
      if (err) {
        console.error('[generateKeyPair] Error:', err);
        reject(err);
        return;
      }
      const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
      const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
      resolve({
        publicKey: publicKeyPem,
        privateKey: privateKeyPem,
      });
    });
  });
};

// === Encrypt Private Key with AES-CBC + PBKDF2 ===
export const encryptPrivateKey = async (privateKeyPem, password) => {
  const salt = forge.random.getBytesSync(16);
  const iv = forge.random.getBytesSync(16);

  const key = forge.pkcs5.pbkdf2(password, salt, 10000, 32, forge.md.sha256.create());

  const cipher = forge.cipher.createCipher("AES-CBC", key);
  cipher.start({ iv });
  cipher.update(forge.util.createBuffer(privateKeyPem, "utf8"));
  cipher.finish();

  const encrypted = cipher.output.getBytes();

  return {
    cipherText: forge.util.encode64(encrypted),
    iv: forge.util.encode64(iv),
    salt: forge.util.encode64(salt),
  };
};

// === Decrypt Private Key with AES-CBC + PBKDF2 ===
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

    return decipher.output.toString();
  } catch (err) {
    console.error("[decryptPrivateKey] Decryption error details:", {
      error: err.message,
      saltLength: saltB64?.length,
      ivLength: ivB64?.length,
      encryptedLength: encryptedPem?.length,
    });
    throw new Error("Failed to decrypt. Check password and try again.");
  }
};

// === Decrypt Message (Hybrid RSA-AES) ===
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
    const aesKeyString = privateKey.decrypt(encryptedKeyBytes, "RSA-OAEP");

    const ivBytes = forge.util.decode64(message.iv);
    const encryptedContentBytes = forge.util.decode64(message.encryptedContent);

    const decipher = forge.cipher.createDecipher("AES-CBC", aesKeyString);
    decipher.start({ iv: ivBytes });
    decipher.update(forge.util.createBuffer(encryptedContentBytes));
    const success = decipher.finish();

    if (!success) {
      throw new Error("AES-CBC decryption failed");
    }

    return decipher.output.toString();
  } catch (err) {
    console.error("[decryptMessage] Message decryption failed:", err);
    return `[Decryption failed: ${err.message}]`;
  }
};

// === Encrypt Message for Students (Hybrid RSA-AES) ===
export const encryptMessageForStudents = async (plainText, students) => {
  try {
    if (!plainText || typeof plainText !== 'string') {
      throw new Error('Invalid message: must be a non-empty string');
    }

    // Generate 32-byte AES key
    const aesKeyBytes = forge.random.getBytesSync(32);

    // Generate 16-byte IV for AES-CBC
    const ivBytes = forge.random.getBytesSync(16);

    // Convert to strings for forge cipher
    const aesKeyString = aesKeyBytes;
    const ivString = ivBytes;

    // AES Encryption
    const cipher = forge.cipher.createCipher('AES-CBC', aesKeyString);
    cipher.start({ iv: ivString });
    cipher.update(forge.util.createBuffer(plainText, 'utf8'));
    const success = cipher.finish();

    if (!success) {
      throw new Error('AES encryption failed');
    }

    const encryptedContent = forge.util.encode64(cipher.output.getBytes());
    const iv = forge.util.encode64(ivString);

    // Encrypt AES key with each student's RSA public key
    const encryptedKeys = {};
    for (const student of students) {
      try {
        const publicKeyPem = student.publicKey;
        const publicKey = forge.pki.publicKeyFromPem(publicKeyPem);

        const encryptedAesKeyBytes = publicKey.encrypt(aesKeyString, 'RSA-OAEP');
        encryptedKeys[student._id.toString()] = forge.util.encode64(encryptedAesKeyBytes);

      } catch (e) {
        console.error(`[encryptMessageForStudents] Failed encrypting AES key for student ${student._id}:`, e);
        throw new Error(`Encryption failed for student ${student._id}`);
      }
    }

    return { 
      encryptedContent, 
      iv, 
      encryptedKey: encryptedKeys 
    };
  } catch (error) {
    console.error('[encryptMessageForStudents] Encryption error:', error);
    throw error;
  }
};
