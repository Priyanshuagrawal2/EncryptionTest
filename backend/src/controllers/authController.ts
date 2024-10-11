import cache from "../utils/cache";
import { Request, Response } from "express";
import { base64ToArrayBuffer } from "../utils/utils";
import { randomBytes } from "crypto";
import * as asn1js from "asn1js";
const { subtle } = require("crypto").webcrypto;

export const getCredentials = (req: Request, res: Response) => {
  const { userId } = req.body;
  const credentials = cache.get<UserCreds[]>(userId);
  const challenge = randomBytes(32).toString("base64");
  cache.set("challenge", challenge);
  res.json({ credentials, challenge });
};

export type UserCreds = {
  credentialId: string;
  publicKey: string;
  algorithm: string;
  transports: string;
};

export const setCredentials = (req: Request, res: Response) => {
  const { userId, creds } = req.body;
  let existingCreds = cache.get<UserCreds[]>(userId);
  if (existingCreds?.length) {
    existingCreds.push(creds);
  } else {
    existingCreds = [creds];
  }
  cache.set(userId, existingCreds);
  res.json({ success: true });
};

function derToRawECDSASignature(derSig: ArrayBuffer) {
  const signature = asn1js.fromBER(derSig);

  if ((signature.result.valueBlock as any).value.length !== 2) {
    throw new Error("Invalid ECDSA DER signature format");
  }

  let r = new Uint8Array(
    (signature.result.valueBlock as any).value[0].valueBlock.valueHex
  );
  let s = new Uint8Array(
    (signature.result.valueBlock as any).value[1].valueBlock.valueHex
  );

  // Handle leading zero padding in r and s
  if (r.length === 33 && r[0] === 0) {
    r = r.slice(1); // Remove the leading zero
  }
  if (s.length === 33 && s[0] === 0) {
    s = s.slice(1); // Remove the leading zero
  }

  // Ensure r and s are both 32 bytes
  const rPadding = new Uint8Array(32 - r.length).fill(0);
  const sPadding = new Uint8Array(32 - s.length).fill(0);

  const rawSignature = new Uint8Array(64);
  rawSignature.set(rPadding, 0);
  rawSignature.set(r, 32 - r.length);
  rawSignature.set(sPadding, 32);
  rawSignature.set(s, 64 - s.length);

  return rawSignature;
}

export async function verifySignature(req: Request, res: Response) {
  try {
    const {
      clientDataJSON,
      authenticatorData,
      signature,
      credentialId,
      userId,
    } = req.body;
    const creds = cache.get<UserCreds[]>(userId);
    if (!creds) {
      return res.status(400).json({ error: "Credentials not found" });
    }
    const cred = creds.find((c) =>
      compareBase64Strings(c.credentialId, credentialId)
    );
    if (!cred) {
      return res.status(400).json({ error: "Credential not found" });
    }
    const publicKey = cred.publicKey;
    const algorithm = cred.algorithm;
    if (!publicKey || !algorithm) {
      return res.status(400).json({ error: "Public key not found" });
    }

    const publicKeyBuffer = base64ToArrayBuffer(publicKey);
    const publicKeyObj = await importPublicKey(
      publicKeyBuffer,
      parseInt(algorithm)
    );

    const clientDataBuffer = base64ToArrayBuffer(clientDataJSON);
    const clientDataHash = await subtle.digest("SHA-256", clientDataBuffer);
    const authDataBuffer = base64ToArrayBuffer(authenticatorData);

    const signatureBase = createSignatureBase(authDataBuffer, clientDataHash);
    const signatureBuffer = base64ToArrayBuffer(signature);

    const isValid = await verifySignatureWithPublicKey(
      publicKeyObj,
      signatureBuffer,
      signatureBase,
      parseInt(algorithm)
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

async function importPublicKey(publicKeyBuffer: ArrayBuffer, alg: number) {
  if (alg === -257) {
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
  } else if (alg === -7) {
    return await subtle.importKey(
      "spki",
      publicKeyBuffer,
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["verify"]
    );
  } else {
    throw new Error(`Unsupported algorithm: ${alg}`);
  }
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
  signatureBase: Uint8Array,
  alg: number
) {
  let algorithm = {};
  if (alg === -257) {
    algorithm = { name: "RSASSA-PKCS1-v1_5" };
  } else if (alg === -7) {
    signatureBuffer = derToRawECDSASignature(signatureBuffer);
    algorithm = { name: "ECDSA", hash: { name: "SHA-256" } };
  }

  return await subtle.verify(
    algorithm,
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
