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
