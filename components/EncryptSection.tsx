import React, { useState, useEffect } from 'react';
import { TextArea } from './common/TextArea';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey } from '../types';
import { LockClosedIcon, ClipboardDocumentIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

interface EncryptSectionProps {
  availableKeys: RpgpPublicKey[];
}

export const EncryptSection: React.FC<EncryptSectionProps> = ({ availableKeys }) => {
  const [plaintext, setPlaintext] = useState('');
  const [selectedRecipientKeyId, setSelectedRecipientKeyId] = useState<string>('');
  const [ciphertext, setCiphertext] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (availableKeys.length > 0 && !selectedRecipientKeyId) {
      setSelectedRecipientKeyId(availableKeys[0].keyId);
    }
  }, [availableKeys, selectedRecipientKeyId]);

  const handleEncrypt = async () => {
    if (!plaintext || !selectedRecipientKeyId) {
      setError('Plaintext and a recipient key are required.');
      return;
    }
    setError(null);
    setSuccessMessage(null);
    setCiphertext('');
    setIsLoading(true);
    try {
      const result = await rpgpMockService.encryptMessage({
        recipientKeyIds: [selectedRecipientKeyId],
        plaintext,
      });
      setCiphertext(result);
      setSuccessMessage('XWing encryption complete. Shared secret established using ML-KEM-768 and X25519.');
    } catch (e: any) {
      setError(e.message || 'Failed to encrypt message.');
    } finally {
      setIsLoading(false);
    }
  };
  
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
      .then(() => setSuccessMessage('Ciphertext copied to clipboard!'))
      .catch(err => setError(`Failed to copy: ${err}`));
  };

  const downloadFile = (content: string, filename: string) => {
    const element = document.createElement('a');
    const file = new Blob([content], { type: 'text/plain;charset=utf-8' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };


  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Encrypt with XWing</h2>
      {error && <Alert type="error" message={error} className="mb-4" />}
      {successMessage && !error && <Alert type="success" message={successMessage} className="mb-4" />}
      
      <TextArea
        label="Message Payload"
        id="plaintext-encrypt"
        value={plaintext}
        onChange={(e) => setPlaintext(e.target.value)}
        placeholder="Enter message to encrypt using hybrid post-quantum cryptography..."
        disabled={isLoading}
      />

      <div>
        <label htmlFor="recipientKey" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
          Target Recipient
        </label>
        {availableKeys.length > 0 ? (
          <select
            id="recipientKey"
            value={selectedRecipientKeyId}
            onChange={(e) => setSelectedRecipientKeyId(e.target.value)}
            className="block w-full pl-3 pr-10 py-2 text-base border-neutral-300 dark:border-neutral-600 focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm rounded-md bg-white dark:bg-neutral-700 text-neutral-900 dark:text-neutral-100"
            disabled={isLoading}
          >
            {availableKeys.map(key => (
              <option key={key.keyId} value={key.keyId}>
                {key.userId} (ID: {key.keyId.substring(0,8)}...)
              </option>
            ))}
          </select>
        ) : (
          <Alert type="info" message="Generate a recipient key in 'Key Management' to perform encryption." />
        )}
      </div>
      
      <Button 
        onClick={handleEncrypt} 
        isLoading={isLoading} 
        disabled={isLoading || !plaintext || !selectedRecipientKeyId || availableKeys.length === 0}
        leftIcon={<LockClosedIcon className="h-5 w-5" />}
      >
        Perform XWing Encryption
      </Button>

      {isLoading && <Spinner text="Encapsulating keys and encrypting payload..." />}

      {ciphertext && (
        <div>
          <h3 className="text-xl font-semibold text-neutral-800 dark:text-neutral-200 mt-6 mb-2">Encrypted Armor Block</h3>
          <TextArea
            id="ciphertext-output"
            value={ciphertext}
            readOnly
            rows={8}
            className="font-mono text-xs"
          />
          <div className="flex space-x-2 mt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => downloadFile(ciphertext, `encrypted-${selectedRecipientKeyId.substring(0,8)}.asc`)}
              leftIcon={<ArrowDownTrayIcon className="h-4 w-4" />}
            >
              Download
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => copyToClipboard(ciphertext)}
              leftIcon={<ClipboardDocumentIcon className="h-4 w-4" />}
            >
              Copy
            </Button>
          </div>
        </div>
      )}
    </div>
  );
};