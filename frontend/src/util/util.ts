import {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationCredential,
  AuthenticationCredential,
} from "@simplewebauthn/types";
import { base64url } from "./base64url";

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);

  const len = binaryString.length;
  const bytes = new Uint8Array(len);

  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes.buffer;
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binaryString = "";

  for (let i = 0; i < bytes.byteLength; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }

  return btoa(binaryString);
}

export function decodeAttestationData(attestationObject: ArrayBuffer): any {
  const decoder = new TextDecoder();
  const dataView = new DataView(attestationObject);

  // Extract and parse fields as necessary
  const fmt = decoder.decode(attestationObject.slice(0, 2)); // For example, extracting the format
  const attestedCredentialDataLength = dataView.getUint16(2);
  const attestedCredentialData = new Uint8Array(
    attestationObject.slice(4, 4 + attestedCredentialDataLength)
  );

  // Return structured data
  return {
    fmt,
    attestedCredentialData,
  };
}

export interface WebAuthnAuthenticationObject
  extends Omit<PublicKeyCredentialRequestOptionsJSON, "challenge"> {
  hints?: string[];
  customTimeout?: number;
  abortTimeout?: number;
}

export interface WebAuthnRegistrationObject
  extends Omit<
    PublicKeyCredentialCreationOptionsJSON,
    "rp" | "pubKeyCredParams" | "challenge" | "excludeCredentials"
  > {
  hints?: string[];
  credentialsToExclude?: string[];
  customTimeout?: number;
  abortTimeout?: number;
}
export const $: any = document.querySelector.bind(document);

export const getOrigin = (_origin: string, userAgent?: string): string => {
  let origin = _origin;
  if (!userAgent) return origin;

  const appRe = /^[a-zA-z0-9_.]+/;
  const match = userAgent.match(appRe);
  if (match) {
    // Check if UserAgent comes from a supported Android app.
    if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
      const package_names = process.env.ANDROID_PACKAGENAME.split(",").map(
        (name) => name.trim()
      );
      const hashes = process.env.ANDROID_SHA256HASH.split(",").map((hash) =>
        hash.trim()
      );
      const appName = match[0];
      for (let i = 0; i < package_names.length; i++) {
        if (appName === package_names[i]) {
          // We recognize this app, so use the corresponding hash.
          const octArray = hashes[i].split(":").map((h) => parseInt(h, 16));
          // @ts-ignore
          const androidHash = isoBase64URL.fromBuffer(octArray);
          origin = `android:apk-key-hash:${androidHash}`;
          break;
        }
      }
    }
  }

  return origin;
};

export async function parseAuthenticationCredential(
  cred: AuthenticationCredential
): Promise<any> {
  const userHandle = cred.response.userHandle
    ? base64url.encode(cred.response.userHandle)
    : undefined;

  const credJSON = {
    id: cred.id,
    rawId: cred.id,
    type: cred.type,
    response: {
      clientDataJSON: {},
      authenticatorData: {},
      signature: base64url.encode(cred.response.signature),
      userHandle,
    },
    clientExtensionResults: {},
  };

  const decoder = new TextDecoder("utf-8");
  credJSON.response.clientDataJSON = JSON.parse(
    decoder.decode(cred.response.clientDataJSON)
  );
  credJSON.response.authenticatorData = await parseAuthenticatorData(
    new Uint8Array(cred.response.authenticatorData)
  );

  credJSON.clientExtensionResults = parseClientExtensionResults(cred);

  return credJSON;
}

async function parseAuthenticatorData(buffer: any): Promise<any> {
  const authData = {
    rpIdHash: "",
    flags: {
      up: false,
      uv: false,
      be: false,
      bs: false,
      at: false,
      ed: false,
    },
  };

  const rpIdHash = buffer.slice(0, 32);
  buffer = buffer.slice(32);
  authData.rpIdHash = [...rpIdHash]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

  const flags = buffer.slice(0, 1)[0];
  buffer = buffer.slice(1);
  authData.flags = {
    up: !!(flags & (1 << 0)),
    uv: !!(flags & (1 << 2)),
    be: !!(flags & (1 << 3)),
    bs: !!(flags & (1 << 4)),
    at: !!(flags & (1 << 6)),
    ed: !!(flags & (1 << 7)),
  };

  return authData;
}

function parseClientExtensionResults(
  credential: RegistrationCredential | AuthenticationCredential
): AuthenticationExtensionsClientOutputs {
  const clientExtensionResults: AuthenticationExtensionsClientOutputs = {};
  if (credential.getClientExtensionResults) {
    const extensions: AuthenticationExtensionsClientOutputs =
      credential.getClientExtensionResults();
    if (extensions.credProps) {
      clientExtensionResults.credProps = extensions.credProps;
    }
  }
  return clientExtensionResults;
}

export function getBrowserInfo(userAgent: string) {
  let os = "Unknown OS";
  let browserName = "Unknown Browser";

  // Check for OS
  if (userAgent.includes("Win")) {
    os = "Windows";
  } else if (userAgent.includes("Mac")) {
    os = "MacOS";
  } else if (userAgent.includes("Linux")) {
    os = "Linux";
  } else if (userAgent.includes("iPhone")) {
    os = "iOS (iPhone)";
  } else if (userAgent.includes("iPad")) {
    os = "iOS (iPad)";
  } else if (userAgent.includes("Android")) {
    os = "Android";
  }

  // Check for browser
  if (userAgent.includes("Chrome")) {
    browserName = "Chrome";
  } else if (userAgent.includes("Firefox")) {
    browserName = "Firefox";
  } else if (userAgent.includes("Safari") && !userAgent.includes("Chrome")) {
    browserName = "Safari";
  } else if (userAgent.includes("MSIE") || userAgent.includes("Trident")) {
    browserName = "Internet Explorer";
  } else if (userAgent.includes("Edge")) {
    browserName = "Microsoft Edge";
  } else if (userAgent.includes("Opera") || userAgent.includes("OPR")) {
    browserName = "Opera";
  }

  return {
    os: os,
    browser: browserName,
  };
}
