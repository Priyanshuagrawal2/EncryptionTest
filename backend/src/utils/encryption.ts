import crypto from "crypto";

export function hashPassword(password: string): string {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex")
    .slice(0, 16);
}

export function deriveKey(secret: string): Buffer {
  return crypto.pbkdf2Sync(secret, "salt", 100000, 32, "sha256");
}

export function encryptString(text: string, secret: string): string {
  const key = deriveKey(secret);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}
