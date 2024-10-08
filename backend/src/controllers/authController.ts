import { Request, Response } from "express";
import cache from "../utils/cache";
import { base64ToArrayBuffer } from "../utils/utils";
import { randomBytes } from "crypto";
const { subtle } = require("crypto").webcrypto;

export const getCredentials = (req: Request, res: Response) => {
  const credentialId = cache.get("credentialId");
  const challenge = randomBytes(32).toString("base64");
  cache.set("challenge", challenge);
  res.json({ credentialId, challenge });
};

export const setCredentials = (req: Request, res: Response) => {
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

    const publicKeyBuffer = base64ToArrayBuffer(publicKey);
    const publicKeyObj = await importPublicKey(publicKeyBuffer);

    const clientDataBuffer = base64ToArrayBuffer(clientDataJSON);
    const clientDataHash = await subtle.digest("SHA-256", clientDataBuffer);
    const authDataBuffer = base64ToArrayBuffer(authenticatorData);

    const signatureBase = createSignatureBase(authDataBuffer, clientDataHash);
    const signatureBuffer = base64ToArrayBuffer(signature);

    const isValid = await verifySignatureWithPublicKey(
      publicKeyObj,
      signatureBuffer,
      signatureBase
    );

    if (isValid) {
      const challenge = cache.get<string>("challenge");
      if (!challenge) {
        return res.status(400).json({ error: "Challenge not found" });
      }
      const isValidChallenge = await validateChallenge(
        challenge,
        clientDataBuffer
      );
      if (!isValidChallenge) {
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

async function importPublicKey(publicKeyBuffer: ArrayBuffer) {
  return await subtle.importKey(
    "spki",
    publicKeyBuffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: { name: "SHA-256" },
    },
    false,
    ["verify"]
  );
}

function createSignatureBase(
  authDataBuffer: ArrayBuffer,
  clientDataHash: ArrayBuffer
) {
  const signatureBase = new Uint8Array(
    authDataBuffer.byteLength + clientDataHash.byteLength
  );
  signatureBase.set(new Uint8Array(authDataBuffer), 0);
  signatureBase.set(new Uint8Array(clientDataHash), authDataBuffer.byteLength);
  return signatureBase;
}

async function verifySignatureWithPublicKey(
  publicKeyObj: CryptoKey,
  signatureBuffer: ArrayBuffer,
  signatureBase: Uint8Array
) {
  return await subtle.verify(
    { name: "RSASSA-PKCS1-v1_5" },
    publicKeyObj,
    signatureBuffer,
    signatureBase
  );
}

async function validateChallenge(
  challenge: string,
  clientDataBuffer: ArrayBuffer
) {
  const parsedClientData = JSON.parse(Buffer.from(clientDataBuffer).toString());
  return compareBase64Strings(parsedClientData.challenge, challenge!);
}
const base64ToStandard = (str: string) => {
  // Convert URL-safe Base64 to standard Base64
  return str.replace(/_/g, "/").replace(/-/g, "+");
};

const decodeBase64 = (str: string) => {
  // Decode Base64 string
  return Buffer.from(str, "base64").toString("utf-8");
};

const compareBase64Strings = (str1: string, str2: string) => {
  const decodedStr1 = decodeBase64(base64ToStandard(str1));
  const decodedStr2 = decodeBase64(base64ToStandard(str2));
  return decodedStr1 === decodedStr2;
};
