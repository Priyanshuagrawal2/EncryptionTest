import cache from "../utils/cache";
import { Request, Response } from "express";
import { base64ToArrayBuffer } from "../utils/utils";
import { createHash, randomBytes } from "crypto";
import * as asn1js from "asn1js";
const { subtle } = require("crypto").webcrypto;
import { generateOTP, verifyOTP } from "../utils/otpUtils";
import { sendOTP } from "../utils/emailUtils";
import { generateRegistrationOptions } from "@simplewebauthn/server";

export async function getRegisterOptions(req: Request, res: Response) {
  const encoder = new TextEncoder();
  const name = "Unnamed User";
  const displayName = "Unnamed User";
  const data = encoder.encode(`${name}${displayName}`);
  const userId = createHash("sha256").update(data).digest();
  const options = await generateRegistrationOptions({
    rpName: "RP_NAME",
    userID: userId,
    userName: "user.name",
    userDisplayName: "user.displayName",
    rpID: "localhost",
    timeout: 6000,
    // Prompt users for additional information about the authenticator.
    attestationType: "none",
    // Prevent users from re-registering existing authenticators
    // excludeCredentials,
    authenticatorSelection: { userVerification: "required" },
    // extensions,
  });
  return res.json({ options });
}

/**
 * Retrieves user credentials and generates a challenge.
 * @param {Request} req - Express request object containing userId in the body.
 * @param {Response} res - Express response object.
 * @returns {void}
 */
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

/**
 * Stores user credentials in the cache.
 * @param {Request} req - Express request object containing userId and creds in the body.
 * @param {Response} res - Express response object.
 * @returns {void}
 */
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

/**
 * Converts a DER-encoded ECDSA signature to raw format.
 */
function derToRawECDSASignature(derSig: ArrayBuffer): Uint8Array {
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

/**
 * Verifies the signature provided by the client.
 * @param {Request} req - Express request object containing signature data.
 * @param {Response} res - Express response object.
 * @returns {Promise<void>}
 */
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

/**
 * Imports a public key for verification.
 * @param {ArrayBuffer} publicKeyBuffer - Public key buffer.
 * @param {number} alg - Algorithm identifier.
 * @returns {Promise<CryptoKey>} Imported public key.
 */
async function importPublicKey(
  publicKeyBuffer: ArrayBuffer,
  alg: number
): Promise<CryptoKey> {
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

/**
 * Creates the base for signature verification.
 */
function createSignatureBase(
  authDataBuffer: ArrayBuffer,
  clientDataHash: ArrayBuffer
): Uint8Array {
  const signatureBase = new Uint8Array(
    authDataBuffer.byteLength + clientDataHash.byteLength
  );
  signatureBase.set(new Uint8Array(authDataBuffer), 0);
  signatureBase.set(new Uint8Array(clientDataHash), authDataBuffer.byteLength);
  return signatureBase;
}

/**
 * Verifies the signature using the public key.
 */
async function verifySignatureWithPublicKey(
  publicKeyObj: CryptoKey,
  signatureBuffer: ArrayBuffer,
  signatureBase: Uint8Array,
  alg: number
): Promise<boolean> {
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

/**
 * Validates the challenge in the client data.
 */
async function validateChallenge(
  challenge: string,
  clientDataBuffer: ArrayBuffer
): Promise<boolean> {
  const parsedClientData = JSON.parse(Buffer.from(clientDataBuffer).toString());
  return compareBase64Strings(parsedClientData.challenge, challenge!);
}

/**
 * Converts URL-safe Base64 to standard Base64.
 */
function base64ToStandard(str: string): string {
  // Convert URL-safe Base64 to standard Base64
  return str.replace(/_/g, "/").replace(/-/g, "+");
}

/**
 * Decodes a Base64 string to UTF-8.
 */
function decodeBase64(str: string): string {
  // Decode Base64 string
  return Buffer.from(str, "base64").toString("utf-8");
}

/**
 * Compares two Base64 strings after decoding.
 */
function compareBase64Strings(str1: string, str2: string): boolean {
  const decodedStr1 = decodeBase64(base64ToStandard(str1));
  const decodedStr2 = decodeBase64(base64ToStandard(str2));
  return decodedStr1 === decodedStr2;
}

/**
 * Generates and sends an OTP to the provided email.
 */
export async function requestOTP(req: Request, res: Response) {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const otp = generateOTP();
  cache.set(`otp:${email}`, otp, 600); // Store OTP for 10 minutes

  try {
    sendOTP(email, otp);
    res.json({ success: true, message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error sending OTP:", error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
}

/**
 * Verifies the OTP and creates a credential challenge if valid.
 * @param {Request} req - Express request object containing email and OTP in the body.
 * @param {Response} res - Express response object.
 * @returns {Promise<void>}
 */
export const verifyOTPAndCreateCredential = async (
  req: Request,
  res: Response
) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP are required" });
  }

  const storedOTP = cache.get<string>(`otp:${email}`);

  if (!storedOTP || !verifyOTP(otp, storedOTP)) {
    return res.status(400).json({ error: "Invalid OTP" });
  }

  // OTP is valid, proceed with credential creation
  const challenge = randomBytes(32).toString("base64");
  cache.set("challenge", challenge);
  res.json({ success: true, challenge });
};
