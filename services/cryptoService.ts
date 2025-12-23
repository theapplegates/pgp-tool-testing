import { KitchenSink_ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';

// Utility functions for encoding/decoding
const bytesToBase64 = (bytes: Uint8Array): string => {
  return btoa(String.fromCharCode(...bytes));
};

const base64ToBytes = (base64: string): Uint8Array => {
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
};

const textToBytes = (text: string): Uint8Array => {
  return new TextEncoder().encode(text);
};

const bytesToText = (bytes: Uint8Array): string => {
  return new TextDecoder().decode(bytes);
};

// In-memory key storage (in production, this would be in secure storage)
let keyStorage: Map<string, RpgpKeyPair> = new Map();

const generateRandomId = (length = 8): string =>
  Array.from(randomBytes(length / 2))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

const createArmoredKey = (type: string, userId: string, keyId: string, algorithm: string, keyData: string): string => {
  return `-----BEGIN PGP ${type} BLOCK-----
Version: Noble Post-Quantum Crypto
Comment: XWing (ML-KEM-768 + X25519) + Ed25519

KeyID: ${keyId}
Algorithm: ${algorithm}
UserID: ${userId}
KeyData: ${keyData}
-----END PGP ${type} BLOCK-----`;
};

const parseArmoredKey = (armored: string): { keyId: string; keyData: string } | null => {
  const keyIdMatch = armored.match(/KeyID: ([A-F0-9]+)/);
  const keyDataMatch = armored.match(/KeyData: ([A-Za-z0-9+/=]+)/);

  if (!keyIdMatch || !keyDataMatch) return null;

  return {
    keyId: keyIdMatch[1],
    keyData: keyDataMatch[1]
  };
};

// Simple XOR-based encryption for passphrase protection (NOT for production!)
const xorEncrypt = (data: Uint8Array, key: Uint8Array): Uint8Array => {
  const result = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = data[i] ^ key[i % key.length];
  }
  return result;
};

// Derive a key from passphrase (simple version - NOT for production!)
const deriveKeyFromPassphrase = (passphrase: string, salt: Uint8Array): Uint8Array => {
  const passphraseBytes = textToBytes(passphrase);
  const key = new Uint8Array(32);

  // Simple key derivation by mixing passphrase with salt
  for (let i = 0; i < 32; i++) {
    key[i] = salt[i % salt.length];
    for (let j = 0; j < passphraseBytes.length; j++) {
      key[i] ^= passphraseBytes[j];
      key[i] = ((key[i] << 1) | (key[i] >> 7)) & 0xFF; // Rotate bits
    }
  }

  return key;
};

export const cryptoService = {
  generateKeyPair: async (params: GenerateKeyParams): Promise<RpgpKeyPair> => {
    const keyId = generateRandomId(16);
    const fingerprint = Array.from({ length: 5 }, () => generateRandomId(8)).join(' ');
    const createdAt = new Date();

    // Generate XWing (ML-KEM-768 + X25519) keypair for encryption using the built-in hybrid KEM
    const xwingKeys = KitchenSink_ml_kem768_x25519.keygen();

    // Generate Ed25519 keypair for signing
    const ed25519PrivateKey = randomBytes(32); // Ed25519 uses 32-byte private keys
    const ed25519PublicKey = ed25519.getPublicKey(ed25519PrivateKey);

    // Combine public keys: XWing public key + Ed25519 public key
    const publicKeyBytes = new Uint8Array([
      ...xwingKeys.publicKey,
      ...ed25519PublicKey
    ]);

    // Combine private keys: XWing secret key + Ed25519 private key
    const privateKeyBytes = new Uint8Array([
      ...xwingKeys.secretKey,
      ...ed25519PrivateKey
    ]);

    // Apply passphrase encryption if provided
    let finalPrivateKeyBytes = privateKeyBytes;
    if (params.passphrase && params.passphrase.length > 0) {
      const salt = randomBytes(16);

      // Derive key from passphrase
      const passphraseKey = deriveKeyFromPassphrase(params.passphrase, salt);

      // Encrypt the private key
      const encrypted = xorEncrypt(privateKeyBytes, passphraseKey);

      // Store salt + encrypted key (no need to store passphrase hash separately)
      finalPrivateKeyBytes = new Uint8Array([
        ...salt,
        ...encrypted
      ]);
    }

    const algorithm = 'XWing (ML-KEM-768 + X25519) + Ed25519';

    const keyPair: RpgpKeyPair = {
      keyId,
      fingerprint,
      userId: params.userId,
      algorithm,
      publicKeyArmored: createArmoredKey('PUBLIC KEY', params.userId, keyId, algorithm, bytesToBase64(publicKeyBytes)),
      privateKeyArmored: createArmoredKey('PRIVATE KEY', params.userId, keyId, algorithm, bytesToBase64(finalPrivateKeyBytes)),
      createdAt,
    };

    keyStorage.set(keyId, keyPair);
    return keyPair;
  },

  getPublicKey: async (keyId: string): Promise<RpgpPublicKey | undefined> => {
    const key = keyStorage.get(keyId);
    if (key) {
      const { privateKeyArmored, ...publicKey } = key;
      return publicKey;
    }
    return undefined;
  },

  getAllPublicKeys: async (): Promise<RpgpPublicKey[]> => {
    return Array.from(keyStorage.values()).map(kp => {
      const { privateKeyArmored, ...publicKeyDetails } = kp;
      return publicKeyDetails;
    });
  },

  encryptMessage: async (params: EncryptParams): Promise<string> => {
    if (params.recipientKeyIds.length === 0) {
      throw new Error('At least one recipient key is required');
    }

    const recipientKeyId = params.recipientKeyIds[0];
    const recipientKey = keyStorage.get(recipientKeyId);

    if (!recipientKey) {
      throw new Error(`Recipient key ${recipientKeyId} not found`);
    }

    const parsed = parseArmoredKey(recipientKey.publicKeyArmored);
    if (!parsed) {
      throw new Error('Invalid public key format');
    }

    const publicKeyBytes = base64ToBytes(parsed.keyData);

    // Extract XWing public key (everything except last 32 bytes which is Ed25519)
    const xwingPublicKey = publicKeyBytes.slice(0, -32);

    // Use XWing KEM to encapsulate and get shared secret
    const { ciphertext: kemCiphertext, sharedSecret } = KitchenSink_ml_kem768_x25519.encapsulate(xwingPublicKey);

    // Use the shared secret to encrypt the message with XChaCha20-Poly1305
    const nonce = randomBytes(24); // XChaCha20 uses 24-byte nonce
    const plaintextBytes = textToBytes(params.plaintext);

    // Create cipher and encrypt
    const cipher = xchacha20poly1305(sharedSecret, nonce);
    const encryptedData = cipher.encrypt(plaintextBytes);

    // Combine: KEM ciphertext + nonce + encrypted data
    const finalCiphertext = new Uint8Array([
      ...kemCiphertext,
      ...nonce,
      ...encryptedData
    ]);

    const armoredCiphertext = `-----BEGIN PGP MESSAGE-----
Version: Noble Post-Quantum Crypto
Comment: Encrypted with XWing (ML-KEM-768 + X25519)

Recipients: ${params.recipientKeyIds.join(', ')}
CipherData: ${bytesToBase64(finalCiphertext)}
-----END PGP MESSAGE-----`;

    return armoredCiphertext;
  },

  decryptMessage: async (params: DecryptParams): Promise<string> => {
    const key = keyStorage.get(params.privateKeyId);
    if (!key) {
      throw new Error('Private key not found');
    }

    const parsed = parseArmoredKey(key.privateKeyArmored);
    if (!parsed) {
      throw new Error('Invalid private key format');
    }

    let privateKeyBytes = base64ToBytes(parsed.keyData);

    // Check if key is passphrase-protected (has salt + hash prefix)
    const xwingSecretKeySize = 2400; // ML-KEM-768 secret key size
    const ed25519PrivateKeySize = 32;
    const expectedUnencryptedSize = xwingSecretKeySize + ed25519PrivateKeySize;

    if (privateKeyBytes.length > expectedUnencryptedSize) {
      // Key is encrypted
      if (!params.passphrase) {
        throw new Error('Passphrase required for this key');
      }

      const salt = privateKeyBytes.slice(0, 16);
      const encrypted = privateKeyBytes.slice(16);

      // Derive key from passphrase using the same method as encryption
      const passphraseKey = deriveKeyFromPassphrase(params.passphrase, salt);

      // Decrypt the private key
      privateKeyBytes = xorEncrypt(encrypted, passphraseKey);
    }

    // Extract XWing secret key (first 2400 bytes)
    const xwingSecretKey = privateKeyBytes.slice(0, xwingSecretKeySize);

    // Parse ciphertext
    const cipherMatch = params.ciphertext.match(/CipherData: ([A-Za-z0-9+/=]+)/);
    if (!cipherMatch) {
      throw new Error('Invalid ciphertext format');
    }

    const ciphertextBytes = base64ToBytes(cipherMatch[1]);

    // Extract components
    const kemCiphertextSize = 1120; // XWing ciphertext size
    const nonceSize = 24;

    const kemCiphertext = ciphertextBytes.slice(0, kemCiphertextSize);
    const nonce = ciphertextBytes.slice(kemCiphertextSize, kemCiphertextSize + nonceSize);
    const encryptedData = ciphertextBytes.slice(kemCiphertextSize + nonceSize);

    // Decapsulate to get shared secret
    const sharedSecret = KitchenSink_ml_kem768_x25519.decapsulate(kemCiphertext, xwingSecretKey);

    // Decrypt the data
    const cipher = xchacha20poly1305(sharedSecret, nonce);
    const decryptedBytes = cipher.decrypt(encryptedData);

    return bytesToText(decryptedBytes);
  },

  signMessage: async (params: SignParams): Promise<string> => {
    const key = keyStorage.get(params.privateKeyId);
    if (!key) {
      throw new Error('Private key not found');
    }

    const parsed = parseArmoredKey(key.privateKeyArmored);
    if (!parsed) {
      throw new Error('Invalid private key format');
    }

    let privateKeyBytes = base64ToBytes(parsed.keyData);

    // Handle passphrase-protected keys
    const xwingSecretKeySize = 2400;
    const ed25519PrivateKeySize = 32;
    const expectedUnencryptedSize = xwingSecretKeySize + ed25519PrivateKeySize;

    if (privateKeyBytes.length > expectedUnencryptedSize) {
      if (!params.passphrase) {
        throw new Error('Passphrase required for this key');
      }

      const salt = privateKeyBytes.slice(0, 16);
      const encrypted = privateKeyBytes.slice(16);

      // Derive key from passphrase
      const passphraseKey = deriveKeyFromPassphrase(params.passphrase, salt);

      // Decrypt the private key
      privateKeyBytes = xorEncrypt(encrypted, passphraseKey);
    }

    // Extract Ed25519 private key (last 32 bytes)
    const ed25519PrivateKey = privateKeyBytes.slice(xwingSecretKeySize, xwingSecretKeySize + ed25519PrivateKeySize);

    // Sign the message
    const messageBytes = textToBytes(params.message);
    const signature = ed25519.sign(messageBytes, ed25519PrivateKey);

    const signatureBlock = `-----BEGIN PGP SIGNATURE-----
Version: Noble Post-Quantum Crypto
Comment: Signed with Ed25519

KeyID: ${params.privateKeyId}
Signature: ${bytesToBase64(signature)}
-----END PGP SIGNATURE-----`;

    const signedMessage = `-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

${params.message}
${signatureBlock}`;

    return signedMessage;
  },

  createDetachedSignature: async (params: SignParams): Promise<string> => {
    const key = keyStorage.get(params.privateKeyId);
    if (!key) {
      throw new Error('Private key not found');
    }

    const parsed = parseArmoredKey(key.privateKeyArmored);
    if (!parsed) {
      throw new Error('Invalid private key format');
    }

    let privateKeyBytes = base64ToBytes(parsed.keyData);

    // Handle passphrase-protected keys
    const xwingSecretKeySize = 2400;
    const ed25519PrivateKeySize = 32;
    const expectedUnencryptedSize = xwingSecretKeySize + ed25519PrivateKeySize;

    if (privateKeyBytes.length > expectedUnencryptedSize) {
      if (!params.passphrase) {
        throw new Error('Passphrase required for this key');
      }

      const salt = privateKeyBytes.slice(0, 16);
      const encrypted = privateKeyBytes.slice(16);

      // Derive key from passphrase
      const passphraseKey = deriveKeyFromPassphrase(params.passphrase, salt);

      // Decrypt the private key
      privateKeyBytes = xorEncrypt(encrypted, passphraseKey);
    }

    // Extract Ed25519 private key
    const ed25519PrivateKey = privateKeyBytes.slice(xwingSecretKeySize, xwingSecretKeySize + ed25519PrivateKeySize);

    // Sign the message
    const messageBytes = textToBytes(params.message);
    const signature = ed25519.sign(messageBytes, ed25519PrivateKey);

    return `-----BEGIN PGP SIGNATURE-----
Version: Noble Post-Quantum Crypto
Comment: Signed with Ed25519

KeyID: ${params.privateKeyId}
Signature: ${bytesToBase64(signature)}
-----END PGP SIGNATURE-----`;
  },

  verifyMessage: async (params: VerifyParams): Promise<{isValid: boolean, message: string}> => {
    const key = keyStorage.get(params.signerKeyId);
    if (!key) {
      return {
        isValid: false,
        message: `Signer's public key not found for KeyID ${params.signerKeyId}`
      };
    }

    const parsed = parseArmoredKey(key.publicKeyArmored);
    if (!parsed) {
      return {
        isValid: false,
        message: 'Invalid public key format'
      };
    }

    const publicKeyBytes = base64ToBytes(parsed.keyData);

    // Extract Ed25519 public key (last 32 bytes)
    const ed25519PublicKey = publicKeyBytes.slice(-32);

    // Parse signature
    const signatureMatch = params.signature.match(/Signature: ([A-Za-z0-9+/=]+)/);
    if (!signatureMatch) {
      return {
        isValid: false,
        message: 'Invalid signature format'
      };
    }

    const signatureBytes = base64ToBytes(signatureMatch[1]);
    const messageBytes = textToBytes(params.message);

    try {
      const isValid = ed25519.verify(signatureBytes, messageBytes, ed25519PublicKey);

      return {
        isValid,
        message: isValid
          ? `Signature verification SUCCESSFUL with Ed25519 key ${params.signerKeyId}`
          : `Signature verification FAILED for key ${params.signerKeyId}`
      };
    } catch (error) {
      return {
        isValid: false,
        message: `Signature verification error: ${error instanceof Error ? error.message : 'Unknown error'}`
      };
    }
  }
};
