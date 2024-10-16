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
