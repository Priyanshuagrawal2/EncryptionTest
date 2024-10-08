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
