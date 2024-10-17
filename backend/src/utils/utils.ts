export async function verifySignature(
  clientDataJSON: string,
  authenticatorData: string,
  signature: Uint8Array,
  publicKey: string
) {
  const encoder = new TextEncoder();

  // Convert to ArrayBuffer for verification
  const data = encoder.encode(clientDataJSON + authenticatorData);

  const publicKeyObj = await crypto.subtle.importKey(
    "spki",
    new TextEncoder().encode(publicKey),
    { name: "ECDSA", hash: { name: "SHA-256" } },
    false,
    ["verify"]
  );

  // Verify the signature
  const isValid = await crypto.subtle.verify(
    "ECDSA",
    publicKeyObj,
    signature,
    data
  );
  return isValid;
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

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
