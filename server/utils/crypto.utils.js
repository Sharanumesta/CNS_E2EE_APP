import crypto from 'crypto';

// Generate RSA key pair
function generateKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// Encrypt with AES-256
function encryptMessage(message, publicKey) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const encryptedKey = crypto.publicEncrypt(publicKey, aesKey);

  return {
    encryptedContent: encrypted,
    iv: iv.toString('hex'),
    encryptedKey: encryptedKey.toString('base64'),
  };
}

// Decrypt message
function decryptMessage(encryptedData, privateKey) {
  const aesKey = crypto.privateDecrypt(
    privateKey,
    Buffer.from(encryptedData.encryptedKey, 'base64')
  );
  const iv = Buffer.from(encryptedData.iv, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted = decipher.update(encryptedData.encryptedContent, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

export { generateKeys, encryptMessage, decryptMessage };
