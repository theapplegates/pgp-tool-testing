
export const PRIMARY_SIGNING_ALGORITHM = "SLH-DSA-SHA2-256s + Ed25519";
export const ENCRYPTION_SUBKEY_ALGORITHM = "MLKEM1024_X448 (ML-KEM-1024 + X448)";

export const GEMINI_MODEL_TEXT = "gemini-3-flash-preview";

// Mock API Key - In a real application, this would come from process.env.API_KEY
// For this environment, we assume process.env.API_KEY is set.
export const MOCK_API_KEY_INFO = "process.env.API_KEY should be set in the environment.";

export const DEBOUNCE_DELAY = 300; // ms
