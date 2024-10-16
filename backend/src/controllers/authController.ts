import cache from "../utils/cache";
import express, { Request, Response } from "express";
import { base64ToArrayBuffer, getOrigin } from "../utils/utils";
import { createHash, randomBytes } from "crypto";
import * as asn1js from "asn1js";
const { subtle } = require("crypto").webcrypto;
import { generateOTP, verifyOTP } from "../utils/otpUtils";
import { sendOTP } from "../utils/emailUtils";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import {
  AuthenticationResponseJSON,
  AuthenticatorSelectionCriteria,
  AuthenticatorDevice,
  AttestationConveyancePreference,
  PublicKeyCredentialParameters,
  PublicKeyCredentialUserEntityJSON,
  AuthenticatorTransportFuture,
} from "@simplewebauthn/types";
import {
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server/script/deps";
import { config } from "node:process";
const WEBAUTHN_TIMEOUT = 1000 * 60 * 5; // 5 minutes

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
  cache.set("challenge", options.challenge);
  cache.set("timeout", new Date().getTime() + WEBAUTHN_TIMEOUT);

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
  user_id: string;
  credentialID: string;
  credentialPublicKey: string;
  aaguid: string;
  counter: number;
  registered: number;
  user_verifying: boolean;
  authenticatorAttachment: string;
  credentialDeviceType: string;
  credentialBackedUp: boolean;
  browser: string;
  os: string;
  platform: string;
  transports: string;
  clientExtensionResults: string;
};

/**
 * Stores user credentials in the cache.
 * @param {Request} req - Express request object containing userId and creds in the body.
 * @param {Response} res - Express response object.
 * @returns {void}
 */
export const setCredentials = async (req: Request, res: Response) => {
  const { credential, userId } = req.body;
  console.log(req.body);

  const expectedChallenge = cache.get<string>("challenge")!;
  const expectedRPID = "localhost";
  let expectedOrigin = getOrigin(
    "http://localhost:5173",
    req.get("User-Agent")
  );
  console.log({ expectedChallenge, expectedRPID, expectedOrigin, credential });
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    // Since this is testing the client, verifying the UV flag here doesn't matter.
    requireUserVerification: true,
  });
  const { verified, registrationInfo } = verification;
  console.log({ registrationInfo });
  if (!verified || !registrationInfo) {
    throw new Error("User verification failed.");
  }
  const {
    aaguid,
    credential: { id: credentialID, publicKey: credentialPublicKey, counter },
    credentialDeviceType,
    credentialBackedUp,
  } = registrationInfo;
  const { response, clientExtensionResults } = credential;

  const transports = response.transports || [];

  const base64PublicKey = isoBase64URL.fromBuffer(credentialPublicKey);
  const creds = {
    user_id: "userId",
    credentialID,
    credentialPublicKey: base64PublicKey,
    aaguid,
    counter,
    registered: new Date().getTime(),
    user_verifying: registrationInfo.userVerified,
    authenticatorAttachment: "undefined",
    credentialDeviceType,
    credentialBackedUp,
    browser: req.get("User-Agent"),
    os: req.get("User-Agent"),
    platform: req.get("User-Agent"),
    transports,
    clientExtensionResults,
  };
  // cache.set("publicKey", base64PublicKey);
  // const { userId, creds } = req.body;
  let existingCreds = cache.get<UserCreds[]>(userId);
  if (existingCreds?.length) {
    existingCreds.push(creds as UserCreds);
  } else {
    existingCreds = [creds as UserCreds];
  }
  cache.set("userId", existingCreds);
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

export async function getAuthOptions(req: Request, res: Response) {
  const creds = cache.get<UserCreds[]>("userId")!;
  console.log({ creds });
  const allowCredentials = creds?.map((c) => ({
    id: c.credentialID!,
    transports: c.transports! as unknown as AuthenticatorTransportFuture[],
  }));
  console.log(allowCredentials);
  const options = await generateAuthenticationOptions({
    timeout: 6000,
    allowCredentials,
    userVerification: "required",
    rpID: "localhost",
  });
  cache.set("challenge", options.challenge);
  cache.set("timeout", new Date().getTime() + WEBAUTHN_TIMEOUT);
  res.json({ options });
}

/**
 * Verifies the signature provided by the client.
 * @param {Request} req - Express request object containing signature data.
 * @param {Response} res - Express response object.
 * @returns {Promise<void>}
 */
export async function verifySignature(req: Request, res: Response) {
  const expectedChallenge = cache.get<string>("challenge")!;
  const expectedRPID = "localhost";
  const expectedOrigin = getOrigin(
    "http://localhost:5173",
    req.get("User-Agent")
  );

  try {
    const { credential: claimedCred, userId } = req.body;

    const credentials = cache.get<UserCreds[]>("userId")!;
    console.log({ credentials, claimedCred });
    let storedCred = credentials.find(
      (cred) => cred.credentialID === claimedCred.id
    );
    if (!storedCred) {
      throw new Error("Authenticating credential not found.");
    }

    const credentialPublicKey = isoBase64URL.toBuffer(
      storedCred.credentialPublicKey
    );
    const { counter, transports } = storedCred;

    const credential: WebAuthnCredential = {
      id: storedCred.credentialID,
      publicKey: credentialPublicKey,
      counter,
      transports: transports as unknown as AuthenticatorTransportFuture[],
    };

    console.log("Claimed credential", claimedCred);
    console.log("Stored credential", storedCred);

    const verification = await verifyAuthenticationResponse({
      response: claimedCred,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential,
      // Since this is testing the client, verifying the UV flag here doesn't matter.
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verification;

    if (!verified) {
      throw new Error("User verification failed.");
    }

    storedCred.counter = authenticationInfo.newCounter;

    return res.json(storedCred);
  } catch (error: any) {
    console.error(error);

    return res.status(400).json({ status: false, error: error.message });
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
