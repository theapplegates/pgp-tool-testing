import { GoogleGenAI, GenerateContentResponse, Part } from "@google/genai";
import { GEMINI_MODEL_TEXT } from '../constants';
import { GroundingChunk } from "../types";

// Safety check for environment variables in frontend
const getApiKey = () => {
  try {
    return (window as any).process?.env?.API_KEY || (process as any)?.env?.API_KEY;
  } catch (e) {
    return undefined;
  }
};

const API_KEY = getApiKey();

let ai: GoogleGenAI | null = null;
if (API_KEY) {
  ai = new GoogleGenAI({ apiKey: API_KEY });
}

export const geminiService = {
  explainTerm: async (term: string): Promise<{ explanation: string; groundingChunks?: GroundingChunk[] }> => {
    if (!ai) {
      throw new Error("Gemini API key not configured. Please ensure API_KEY is set in the environment.");
    }
    if (!term.trim()) {
      throw new Error("Term cannot be empty.");
    }

    const prompt = `Explain the cryptographic term "${term}" concisely. Focus on its relevance to post-quantum security or hybrid schemes like XWing (ML-KEM-768 + X25519) if applicable. Use Google Search grounding for accurate links.`;

    try {
      const response: GenerateContentResponse = await ai.models.generateContent({
        model: GEMINI_MODEL_TEXT,
        contents: [{ role: "user", parts: [{text: prompt} as Part] }],
        config: {
          tools: [{googleSearch: {}}],
        }
      });
      
      const explanation = response.text || "No explanation provided by the model.";
      const groundingMetadata = response.candidates?.[0]?.groundingMetadata;
      let groundingChunks: GroundingChunk[] | undefined = undefined;

      if (groundingMetadata && groundingMetadata.groundingChunks && groundingMetadata.groundingChunks.length > 0) {
        groundingChunks = groundingMetadata.groundingChunks
          .filter(chunk => chunk.web && chunk.web.uri && chunk.web.title)
          .map(chunk => ({
             web: {
               uri: chunk.web.uri,
               title: chunk.web.title,
             }
           }));
      }
      
      return { explanation, groundingChunks };

    } catch (error) {
      console.error("Error calling Gemini API:", error);
      if (error instanceof Error) {
         throw new Error(`Gemini API Error: ${error.message}`);
      }
      throw new Error("An unknown error occurred while fetching explanation from Gemini API.");
    }
  },
};