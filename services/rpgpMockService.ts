import { XWing } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha3_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';

/**
 * REAL XWing Cryptographic Service
 * Implements XWing (ML-KEM-768 + X25519) for encryption and ML-DSA-65 + Ed25519 for signatures
 * Uses the official XWing KEM from @noble/post-quantum
 * All hashing uses SHA3-512
 */

const base64Encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const base64Decode = (str: string) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

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
    // 1. Generate Signature Keys (ML-DSA-65 + Ed25519)
    const dsaKeys = ml_dsa65.keygen();
    const edKeys = ed25519.keygen();

    // 2. Generate Encryption Keys using XWing (ML-KEM-768 + X25519)
    const xwingKeys = XWing.keygen();

    const keyId = bytesToHex(sha3_512(concatBytes(dsaKeys.publicKey, edKeys.publicKey))).substring(0, 16).toUpperCase();
    const fingerprint = bytesToHex(sha3_512(concatBytes(dsaKeys.publicKey, edKeys.publicKey))).toUpperCase();
    const formattedFingerprint = fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint;

    const pubObj = {
      dsaPub: base64Encode(dsaKeys.publicKey),
      edPub: base64Encode(edKeys.publicKey),
      xwingPub: base64Encode(xwingKeys.publicKey)
    };

    const privObj = {
      dsaPriv: base64Encode(dsaKeys.secretKey),
      edPriv: base64Encode(edKeys.secretKey),
      xwingPriv: base64Encode(xwingKeys.secretKey)
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
    const xwingPub = base64Decode(pubData.xwingPub);

    // XWing KEM Encapsulation
    const { cipherText, sharedSecret } = XWing.encapsulate(xwingPub);

    // Derive AES-256-GCM key from shared secret using SHA3-512
    const aesKeyBytes = sha3_512(sharedSecret).slice(0, 32);

    // AES-256-GCM Payload Encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      new TextEncoder().encode(params.plaintext)
    );

    const msgData = {
      xwingCt: base64Encode(cipherText),
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

    const xwingPriv = base64Decode(privData.xwingPriv);
    const xwingCt = base64Decode(msgData.xwingCt);

    // XWing KEM Decapsulation
    const sharedSecret = XWing.decapsulate(xwingCt, xwingPriv);

    // Derive AES-256-GCM key from shared secret using SHA3-512
    const aesKeyBytes = sha3_512(sharedSecret).slice(0, 32);

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

    const dsaSig = ml_dsa65.sign(msgBytes, base64Decode(privData.dsaPriv));
    const edSig = ed25519.sign(msgBytes, base64Decode(privData.edPriv));

    const sigData = {
      dsaSig: base64Encode(dsaSig),
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

    const dsaSig = ml_dsa65.sign(msgBytes, base64Decode(privData.dsaPriv));
    const edSig = ed25519.sign(msgBytes, base64Decode(privData.edPriv));

    const sigData = {
      dsaSig: base64Encode(dsaSig),
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
    const dsaOk = ml_dsa65.verify(base64Decode(sigData.dsaSig), msgBytes, base64Decode(pubData.dsaPub));
    const edOk = ed25519.verify(base64Decode(sigData.edSig), msgBytes, base64Decode(pubData.edPub));

    const isValid = dsaOk && edOk;
    return {
      isValid,
      message: isValid
        ? `XWing-grade cryptographic integrity confirmed. Verified hybrid signature (ML-DSA-65 + Ed25519) for identity ${key.userId}.`
        : `Verification FAILED. Signature mismatch or data corruption detected.`
    };
  }
};