import React, { useState, useEffect } from 'react';
import { TextArea } from './common/TextArea';
import { Input } from './common/Input';
import { Button } from './common/Button';
import { Alert } from './common/Alert';
import { Spinner } from './common/Spinner';
import { rpgpMockService } from '../services/rpgpMockService';
import { RpgpPublicKey } from '../types';
import { PencilSquareIcon, ClipboardDocumentIcon, ArrowDownTrayIcon } from '@heroicons/react/24/outline';

interface SignSectionProps {
  availableKeys: RpgpPublicKey[];
}

export const SignSection: React.FC<SignSectionProps> = ({ availableKeys }) => {
  const [message, setMessage] = useState('');
  const [selectedPrivateKeyId, setSelectedPrivateKeyId] = useState<string>('');
  const [passphrase, setPassphrase] = useState('');
  const [signedOutput, setSignedOutput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (availableKeys.length > 0 && !selectedPrivateKeyId) {
      setSelectedPrivateKeyId(availableKeys[0].keyId);
    }
  }, [availableKeys, selectedPrivateKeyId]);

  const handleSign = async (detached: boolean) => {
    if (!message || !selectedPrivateKeyId) {
      setError('Message and a private key are required.');
      return;
    }
    setError(null);
    setSuccessMessage(null);
    setSignedOutput('');
    setIsLoading(true);
    try {
      let result;
      if (detached) {
        result = await rpgpMockService.createDetachedSignature({
            privateKeyId: selectedPrivateKeyId,
            passphrase,
            message,
        });
        setSuccessMessage('Detached hybrid signature created.');
      } else {
        result = await rpgpMockService.signMessage({
            privateKeyId: selectedPrivateKeyId,
            passphrase,
            message,
        });
        setSuccessMessage('Message signed with hybrid construction.');
      }
      setSignedOutput(result);
      
    } catch (e: any) {
      setError(e.message || 'Failed to sign message.');
    } finally {
      setIsLoading(false);
    }
  };
  
  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text)
      .then(() => setSuccessMessage(`${type} copied to clipboard!`))
      .catch(err => setError(`Failed to copy ${type}: ${err}`));
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
      <h2 className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">Hybrid PQ Signature</h2>
      {error && <Alert type="error" message={error} className="mb-4" />}
      {successMessage && !error && <Alert type="success" message={successMessage} className="mb-4" />}

      <TextArea
        label="Message to Sign"
        id="message-sign"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter text to sign using ML-DSA-65 and Ed25519..."
        disabled={isLoading}
      />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
            <label htmlFor="privateKeySign" className="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
            Signing Identity
            </label>
            {availableKeys.length > 0 ? (
            <select
                id="privateKeySign"
                value={selectedPrivateKeyId}
                onChange={(e) => setSelectedPrivateKeyId(e.target.value)}
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
            <Alert type="info" message="Generate a signing key in 'Key Management' first." />
            )}
        </div>
        <Input
          label="Passphrase"
          id="passphrase-sign"
          type="password"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          placeholder="Unlock private key"
          disabled={isLoading || !selectedPrivateKeyId}
        />
      </div>
      
      <div className="flex space-x-4">
        <Button 
            onClick={() => handleSign(false)} 
            isLoading={isLoading} 
            disabled={isLoading || !message || !selectedPrivateKeyId || availableKeys.length === 0}
            leftIcon={<PencilSquareIcon className="h-5 w-5" />}
        >
            Clear-Sign Message
        </Button>
        <Button 
            onClick={() => handleSign(true)} 
            isLoading={isLoading} 
            disabled={isLoading || !message || !selectedPrivateKeyId || availableKeys.length === 0}
            variant="secondary"
            leftIcon={<PencilSquareIcon className="h-5 w-5" />}
        >
            Create Detached Signature
        </Button>
      </div>

      {isLoading && <Spinner text="Calculating ML-DSA and Ed25519 signatures..." />}

      {signedOutput && (
        <div>
          <h3 className="text-xl font-semibold text-neutral-800 dark:text-neutral-200 mt-6 mb-2">Signature Armor Block</h3>
          <TextArea
            id="signed-output"
            value={signedOutput}
            readOnly
            rows={10}
            className="font-mono text-xs"
          />
          <div className="flex space-x-2 mt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => downloadFile(signedOutput, `signature-${selectedPrivateKeyId.substring(0,8)}.asc`)}
              leftIcon={<ArrowDownTrayIcon className="h-4 w-4" />}
            >
              Download
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => copyToClipboard(signedOutput, "Signature block")}
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