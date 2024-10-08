import { Request, Response } from "express";
import cache from "../utils/cache";
import { base64ToArrayBuffer } from "../utils/utils";
import crypto, { randomBytes } from "crypto";
const { subtle } = require("crypto").webcrypto;

import { Buffer } from "buffer";

// Function to retrieve the stored value if needed
export const getStoredValue = (key: string): string | undefined => {
  return cache.get(key);
};

export const getCreds = (req: Request, res: Response) => {
  const credentialId = cache.get("credentialId");
  const challenge = randomBytes(32).toString("base64url");
  cache.set("challenge", challenge);
  res.json({ credentialId, challenge });
};

export const setCreds = (req: Request, res: Response) => {
  const { credentialId, publicKey } = req.body;
  cache.set("credentialId", credentialId);
  cache.set("publicKey", publicKey);
  res.json({ success: true });
};

export async function verifySignature(req: Request, res: Response) {
  try {
    const { clientDataJSON, authenticatorData, signature } = req.body;

    const publicKey = cache.get<string>("publicKey");
    if (!publicKey) {
      return res.status(400).json({ error: "Public key not found" });
    }

    // Convert the public key from base64 to ArrayBuffer
    const publicKeyBuffer = base64ToArrayBuffer(publicKey);

    // Import the public key with correct parameters
    const publicKeyObj = await subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      false,
      ["verify"]
    );

    // Decode and hash clientDataJSON
    const clientDataBuffer = base64ToArrayBuffer(clientDataJSON);
    const clientDataHash = await subtle.digest("SHA-256", clientDataBuffer);

    // Decode authenticatorData
    const authDataBuffer = base64ToArrayBuffer(authenticatorData);

    // Concatenate authenticatorData and clientDataHash
    const signatureBase = new Uint8Array(
      authDataBuffer.byteLength + clientDataHash.byteLength
    );
    signatureBase.set(new Uint8Array(authDataBuffer), 0);
    signatureBase.set(
      new Uint8Array(clientDataHash),
      authDataBuffer.byteLength
    );

    // Decode signature
    const signatureBuffer = base64ToArrayBuffer(signature);

    // Verify the signature
    const isValid = await subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      publicKeyObj,
      signatureBuffer,
      signatureBase
    );

    if (isValid) {
      // Verify the challenge
      const challenge = cache.get("challenge");
      const parsedClientData = JSON.parse(
        Buffer.from(clientDataBuffer).toString()
      );
      if (parsedClientData.challenge !== challenge) {
        return res.status(401).json({ error: "Invalid challenge" });
      }
      res.json({ isValid });
    } else {
      res.status(401).json({ error: "Invalid signature" });
    }
  } catch (error) {
    console.error("Error verifying signature:", error);
    res.status(500).json({ error: "Internal server error" });
  }
}
