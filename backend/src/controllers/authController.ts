import cache from "../utils/cache";
import { Request, Response } from "express";
import { getBrowserInfo, getOrigin } from "../utils/utils";
import { createHash, randomBytes } from "crypto";
import { generateOTP, verifyOTP } from "../utils/otpUtils";
import { sendOTP } from "../utils/emailUtils";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { AuthenticatorTransportFuture } from "@simplewebauthn/types";
import { WebAuthnCredential } from "@simplewebauthn/server/script/deps";

const WEBAUTHN_TIMEOUT = 1000 * 60 * 5; // 5 minutes

export async function getRegisterOptions(req: Request, res: Response) {
  const { username, userId } = req.body;
  const encoder = new TextEncoder();
  const name = userId;
  const displayName = username;
  const data = encoder.encode(`${name}${displayName}`);
  const userIdHash = createHash("sha256").update(data).digest();
  const rpID = process.env.RP_ID || "localhost";
  const existingCreds = cache.get<UserCreds[]>(userId);
  let excludeCredentials: WebAuthnCredential[] = [];
  if (existingCreds?.length) {
    excludeCredentials = existingCreds.map((cred) => ({
      id: cred.credentialID,
      counter: cred.counter,
      publicKey: isoBase64URL.toBuffer(cred.credentialPublicKey),
      transports: cred.transports as unknown as AuthenticatorTransportFuture[],
    }));
  }
  const options = await generateRegistrationOptions({
    rpName: process.env.RP_NAME || "Your Application Name",
    userID: userIdHash,
    userName: userId,
    userDisplayName: displayName,
    rpID,
    timeout: 6000,
    // Prompt users for additional information about the authenticator.
    attestationType: "none",
    // Prevent users from re-registering existing authenticators
    excludeCredentials,
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

  const expectedChallenge = cache.get<string>("challenge")!;
  const expectedRPID = process.env.RP_ID || "localhost";
  let expectedOrigin = getOrigin(
    "http://localhost:5173",
    req.get("User-Agent")
  );
  const verification = await verifyRegistrationResponse({
    response: credential,
    expectedChallenge,
    expectedOrigin,
    expectedRPID,
    requireUserVerification: true,
  });
  const { verified, registrationInfo } = verification;
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
  const browserInfo = getBrowserInfo(req.get("User-Agent")!);
  const creds = {
    user_id: userId,
    credentialID,
    credentialPublicKey: base64PublicKey,
    aaguid,
    counter,
    registered: new Date().getTime(),
    user_verifying: registrationInfo.userVerified,
    credentialDeviceType,
    credentialBackedUp,
    transports,
    browser: browserInfo.browser,
    os: browserInfo.os,
    clientExtensionResults,
  };

  let existingCreds = cache.get<UserCreds[]>(userId);
  if (existingCreds?.length) {
    existingCreds.push(creds as UserCreds);
  } else {
    existingCreds = [creds as UserCreds];
  }

  cache.set(userId, existingCreds);
  res.json({ success: true });
};

export async function getAuthOptions(req: Request, res: Response) {
  const { userId } = req.body;
  const creds = cache.get<UserCreds[]>(userId)!;
  const allowCredentials = creds?.map((c) => ({
    id: c.credentialID!,
    browser: c.browser,
    os: c.os,
    transports: c.transports! as unknown as AuthenticatorTransportFuture[],
  }));

  const options = await generateAuthenticationOptions({
    timeout: 6000,
    allowCredentials,
    userVerification: "required",
    rpID: process.env.RP_ID || "localhost",
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
  const expectedRPID = process.env.RP_ID || "localhost";
  const expectedOrigin = getOrigin(
    "http://localhost:5173",
    req.get("User-Agent")
  );

  try {
    const { credential: claimedCred, userId } = req.body;

    const credentials = cache.get<UserCreds[]>(userId)!;
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

    const verification = await verifyAuthenticationResponse({
      response: claimedCred,
      expectedChallenge,
      expectedOrigin,
      expectedRPID,
      credential,
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
