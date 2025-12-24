import { XWing } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { RpgpPublicKey, RpgpKeyPair, GenerateKeyParams, EncryptParams, DecryptParams, SignParams, VerifyParams } from '../types';
import { PRIMARY_SIGNING_ALGORITHM, ENCRYPTION_SUBKEY_ALGORITHM } from '../constants';

/**
 * REAL XWing Cryptographic Service
 * Implements XWing (ML-KEM-768 + X25519) for encryption and ML-DSA-65 + Ed25519 for signatures
 * Uses the official XWing KEM from @noble/post-quantum
 */

const base64Encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const base64Decode = (str: string) => Uint8Array.from(atob(str), c => c.charCodeAt(0));

// In-memory store for session-based key persistence
let keyStorage: RpgpKeyPair[] = [];

const wrapArmor = (label: string, data: any) => {
  const json = JSON.stringify(data);
  const encoded = base64Encode(new TextEncoder().encode(json));
  return `-----BEGIN ${label}-----\n\n${encoded}\n-----END ${label}-----`;
};

const unwrapArmor = (label: string, armored: string) => {
  const lines = armored.split('\n');
  const dataLine = lines.find(l => l && !l.startsWith('-----') && l.length > 20);
  if (!dataLine) throw new Error(`Invalid armored ${label} block format`);
  const decoded = base64Decode(dataLine);
  return JSON.parse(new TextDecoder().decode(decoded));
};

export const rpgpMockService = {
  generateKeyPair: async (params: GenerateKeyParams): Promise<RpgpKeyPair> => {
    // 1. Generate Signature Keys (ML-DSA-65 + Ed25519)
    const dsaKeys = ml_dsa65.keygen();
    const edPriv = ed25519.utils.randomPrivateKey();
    const edPub = ed25519.getPublicKey(edPriv);

    // 2. Generate Encryption Keys using XWing (ML-KEM-768 + X25519)
    const xwingKeys = XWing.keygen();

    const keyId = bytesToHex(sha256(concatBytes(dsaKeys.publicKey, edPub))).substring(0, 16).toUpperCase();
    const fingerprint = bytesToHex(sha512(concatBytes(dsaKeys.publicKey, edPub))).toUpperCase();

    const pubObj = {
      dsaPub: base64Encode(dsaKeys.publicKey),
      edPub: base64Encode(edPub),
      xwingPub: base64Encode(xwingKeys.publicKey)
    };

    const privObj = {
      dsaPriv: base64Encode(dsaKeys.secretKey),
      edPriv: base64Encode(edPriv),
      xwingPriv: base64Encode(xwingKeys.secretKey)
    };

    const keyPair: RpgpKeyPair = {
      keyId,
      fingerprint: fingerprint.match(/.{1,4}/g)?.join(' ') || fingerprint,
      userId: params.userId,
      algorithm: `${PRIMARY_SIGNING_ALGORITHM} / ${ENCRYPTION_SUBKEY_ALGORITHM}`,
      publicKeyArmored: wrapArmor('PGP PUBLIC KEY BLOCK', pubObj),
      privateKeyArmored: wrapArmor('PGP PRIVATE KEY BLOCK', privObj),
      createdAt: new Date(),
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

    // Derive AES-256-GCM key from shared secret
    const aesKeyBytes = sha256(sharedSecret);

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

    // Derive AES-256-GCM key from shared secret
    const aesKeyBytes = sha256(sharedSecret);

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
    return `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n${params.message}\n\n${signatureArmor}`;
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