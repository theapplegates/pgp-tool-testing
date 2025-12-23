import { cryptoService } from './cryptoService';

// Re-export the real crypto service as rpgpMockService to maintain compatibility
export const rpgpMockService = cryptoService;
