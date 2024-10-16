import {
  CredentialDeviceType,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticatorTransportFuture,
} from "@simplewebauthn/types";

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
