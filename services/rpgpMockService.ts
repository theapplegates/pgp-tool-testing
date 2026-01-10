import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { slh_dsa_sha2_256s } from '@noble/post-quantum/slh-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { x448 } from '@noble/curves/ed448.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';

/**
 * Post-Quantum Cryptographic Service
 * Implements MLKEM1024_X448 hybrid for encryption and SLHDSA256s + Ed25519 for signatures
 * Uses NIST FIPS 203 (ML-KEM-1024) + RFC 7748 (X448) hybrid KEM
 * Uses NIST FIPS 205 (SLH-DSA-SHA2-256s) for hash-based signatures
 * All hashing uses SHA3-512
 */

// Proper base64 encoding that handles large byte arrays
const base64Encode = (bytes: Uint8Array): string => {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

const base64Decode = (str: string): Uint8Array => {
  const binary = atob(str);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

// In-memory store for session-based key persistence
let keyStorage: RpgpKeyPair[] = [];

interface ArmorMetadata {
  userId?: string;
  email?: string;
  created?: Date;
  expires?: Date;
  type?: string;
  usage?: string;
  fingerprint?: string;
}

const wrapArmor = (label: string, data: any, metadata?: ArmorMetadata) => {
  const json = JSON.stringify(data);
  const encoded = base64Encode(new TextEncoder().encode(json));

  let armor = `-----BEGIN ${label}-----\n`;

  // Add metadata as comments
  if (metadata) {
    if (metadata.userId) {
      armor += `Comment: User-ID:\t${metadata.userId}\n`;
    }
    if (metadata.email) {
      armor += `Comment: a.k.a.:\t<${metadata.email}>\n`;
    }
    if (metadata.created) {
      const dateStr = metadata.created.toLocaleString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      });
      armor += `Comment: Created:\t${dateStr}\n`;
    }
    if (metadata.expires) {
      const dateStr = metadata.expires.toLocaleString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
      });
      armor += `Comment: Expires:\t${dateStr}\n`;
    }
    if (metadata.type) {
      armor += `Comment: Type:\t${metadata.type}\n`;
    }
    if (metadata.usage) {
      armor += `Comment: Usage:\t${metadata.usage}\n`;
    }
    if (metadata.fingerprint) {
      armor += `Comment: Fingerprint:\t${metadata.fingerprint}\n`;
    }
  }

  armor += `\n${encoded}\n-----END ${label}-----`;
  return armor;
};

const unwrapArmor = (label: string, armored: string) => {
  const lines = armored.split('\n');
  const dataLine = lines.find(l => l && !l.startsWith('-----') && !l.startsWith('Comment:') && l.trim().length > 20);
  if (!dataLine) throw new Error(`Invalid armored ${label} block format`);
  const decoded = base64Decode(dataLine);
  return JSON.parse(new TextDecoder().decode(decoded));
};

export const rpgpMockService = {
  generateKeyPair: async (params: GenerateKeyParams): Promise<RpgpKeyPair> => {
    // 1. Generate Signature Keys (SLH-DSA-SHA2-256s + Ed25519)
    const slhdsaKeys = slh_dsa_sha2_256s.keygen();
    const edKeys = ed25519.keygen();

    // 2. Generate Encryption Keys using hybrid ML-KEM-1024 + X448
    const mlkemKeys = ml_kem1024.keygen();
    const x448Keys = x448.keygen();
    const x448PrivKey = x448Keys.secretKey;
    const x448PubKey = x448Keys.publicKey;

    const keyId = bytesToHex(sha3_512(concatBytes(slhdsaKeys.publicKey, edKeys.publicKey))).substring(0, 16).toUpperCase();
    const fingerprint = bytesToHex(sha3_512(concatBytes(slhdsaKeys.publicKey, edKeys.publicKey))).toUpperCase();
    const formattedFingerprint = fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint;

    const pubObj = {
      slhdsaPub: base64Encode(slhdsaKeys.publicKey),
      edPub: base64Encode(edKeys.publicKey),
      mlkemPub: base64Encode(mlkemKeys.publicKey),
      x448Pub: base64Encode(x448PubKey)
    };

    const privObj = {
      slhdsaPriv: base64Encode(slhdsaKeys.secretKey),
      edPriv: base64Encode(edKeys.secretKey),
      mlkemPriv: base64Encode(mlkemKeys.secretKey),
      x448Priv: base64Encode(x448PrivKey)
    };

    const createdAt = new Date();
    const expiresAt = new Date(createdAt.getTime() + (3 * 365 * 24 * 60 * 60 * 1000)); // 3 years

    // Extract email from userId if present (format: "Name <email@example.com>")
    const emailMatch = params.userId.match(/<(.+?)>/);
    const email = emailMatch ? emailMatch[1] : undefined;
    const userName = emailMatch ? params.userId.replace(/<.+?>/, '').trim() : params.userId;

    const metadata: ArmorMetadata = {
      userId: userName,
      email,
      created: createdAt,
      expires: expiresAt,
      type: 'Post-Quantum Hybrid (secret key available)',
      usage: 'Signing, Encryption, Certifying User-IDs',
      fingerprint: formattedFingerprint
    };

    const keyPair: RpgpKeyPair = {
      keyId,
      fingerprint: formattedFingerprint,
      userId: params.userId,
      algorithm: `${PRIMARY_SIGNING_ALGORITHM} / ${ENCRYPTION_SUBKEY_ALGORITHM}`,
      publicKeyArmored: wrapArmor('PGP PUBLIC KEY BLOCK', pubObj, metadata),
      privateKeyArmored: wrapArmor('PGP PRIVATE KEY BLOCK', privObj, { ...metadata, type: 'Post-Quantum Hybrid (secret key available)' }),
      createdAt,
    };

    keyStorage.push(keyPair);
    return keyPair;
  },

  getPublicKey: async (keyId: string): Promise<RpgpPublicKey | undefined> => {
    return keyStorage.find(k => k.keyId === keyId);
  },

  getAllPublicKeys: async (): Promise<RpgpPublicKey[]> => {
    return keyStorage;
  },

  encryptMessage: async (params: EncryptParams): Promise<string> => {
    const targetKey = keyStorage.find(k => k.keyId === params.recipientKeyIds[0]);
    if (!targetKey) throw new Error("Recipient key not found");

    const pubData = unwrapArmor('PGP PUBLIC KEY BLOCK', targetKey.publicKeyArmored);
    const mlkemPub = base64Decode(pubData.mlkemPub);
    const x448Pub = base64Decode(pubData.x448Pub);

    // ML-KEM-1024 Encapsulation
    const { cipherText: mlkemCt, sharedSecret: mlkemSS } = ml_kem1024.encapsulate(mlkemPub);

    // X448 Key Agreement
    const x448EphemeralKeys = x448.keygen();
    const x448EphemeralPriv = x448EphemeralKeys.secretKey;
    const x448EphemeralPub = x448EphemeralKeys.publicKey;
    const x448SS = x448.getSharedSecret(x448EphemeralPriv, x448Pub);

    // Combine both shared secrets using SHA3-512
    const combinedSecret = sha3_512(concatBytes(mlkemSS, x448SS));

    // Derive AES-256-GCM key from combined secret
    const aesKeyBytes = combinedSecret.slice(0, 32);

    // AES-256-GCM Payload Encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      new TextEncoder().encode(params.plaintext)
    );

    const msgData = {
      mlkemCt: base64Encode(mlkemCt),
      x448EphPub: base64Encode(x448EphemeralPub),
      iv: base64Encode(iv),
      ct: base64Encode(new Uint8Array(encrypted)),
      recipient: targetKey.keyId
    };

    return wrapArmor('PGP MESSAGE', msgData);
  },

  decryptMessage: async (params: DecryptParams): Promise<string> => {
    const key = keyStorage.find(k => k.keyId === params.privateKeyId);
    if (!key) throw new Error("Private key not found");

    const privData = unwrapArmor('PGP PRIVATE KEY BLOCK', key.privateKeyArmored);
    const msgData = unwrapArmor('PGP MESSAGE', params.ciphertext);

    const mlkemPriv = base64Decode(privData.mlkemPriv);
    const x448Priv = base64Decode(privData.x448Priv);
    const mlkemCt = base64Decode(msgData.mlkemCt);
    const x448EphPub = base64Decode(msgData.x448EphPub);

    // ML-KEM-1024 Decapsulation
    const mlkemSS = ml_kem1024.decapsulate(mlkemCt, mlkemPriv);

    // X448 Key Agreement
    const x448SS = x448.getSharedSecret(x448Priv, x448EphPub);

    // Combine both shared secrets using SHA3-512
    const combinedSecret = sha3_512(concatBytes(mlkemSS, x448SS));

    // Derive AES-256-GCM key from combined secret
    const aesKeyBytes = combinedSecret.slice(0, 32);

    // AES-256-GCM Decryption
    const cryptoKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64Decode(msgData.iv) },
      cryptoKey,
      base64Decode(msgData.ct)
    );

    return new TextDecoder().decode(decrypted);
  },

  signMessage: async (params: SignParams): Promise<string> => {
    const key = keyStorage.find(k => k.keyId === params.privateKeyId);
    if (!key) throw new Error("Signing key not found");

    const privData = unwrapArmor('PGP PRIVATE KEY BLOCK', key.privateKeyArmored);
    const msgBytes = new TextEncoder().encode(params.message);

    const slhdsaSig = slh_dsa_sha2_256s.sign(msgBytes, base64Decode(privData.slhdsaPriv));
    const edSig = ed25519.sign(msgBytes, base64Decode(privData.edPriv));

    const sigData = {
      slhdsaSig: base64Encode(slhdsaSig),
      edSig: base64Encode(edSig),
      signer: key.keyId
    };

    const signatureArmor = wrapArmor('PGP SIGNATURE', sigData);
    return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA3-512\n\n${params.message}\n\n${signatureArmor}`;
  },

  createDetachedSignature: async (params: SignParams): Promise<string> => {
    const key = keyStorage.find(k => k.keyId === params.privateKeyId);
    if (!key) throw new Error("Signing key not found");

    const privData = unwrapArmor('PGP PRIVATE KEY BLOCK', key.privateKeyArmored);
    const msgBytes = new TextEncoder().encode(params.message);

    const slhdsaSig = slh_dsa_sha2_256s.sign(msgBytes, base64Decode(privData.slhdsaPriv));
    const edSig = ed25519.sign(msgBytes, base64Decode(privData.edPriv));

    const sigData = {
      slhdsaSig: base64Encode(slhdsaSig),
      edSig: base64Encode(edSig),
      signer: key.keyId
    };

    return wrapArmor('PGP SIGNATURE', sigData);
  },

  verifyMessage: async (params: VerifyParams): Promise<{isValid: boolean, message: string}> => {
    const key = keyStorage.find(k => k.keyId === params.signerKeyId);
    if (!key) throw new Error("Public key for signer not found");

    const pubData = unwrapArmor('PGP PUBLIC KEY BLOCK', key.publicKeyArmored);
    const sigData = unwrapArmor('PGP SIGNATURE', params.signature);

    const msgBytes = new TextEncoder().encode(params.message);
    const slhdsaOk = slh_dsa_sha2_256s.verify(base64Decode(sigData.slhdsaSig), msgBytes, base64Decode(pubData.slhdsaPub));
    const edOk = ed25519.verify(base64Decode(sigData.edSig), msgBytes, base64Decode(pubData.edPub));

    const isValid = slhdsaOk && edOk;
    return {
      isValid,
      message: isValid
        ? `Post-quantum cryptographic integrity confirmed. Verified hybrid signature (SLH-DSA-SHA2-256s + Ed25519) for identity ${key.userId}.`
        : `Verification FAILED. Signature mismatch or data corruption detected.`
    };
  }
};