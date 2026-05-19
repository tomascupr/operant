import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const PREFIX = "v1";

export function parseMasterKey(raw: string | undefined): Buffer {
  if (!raw) throw new Error("OPERANT_SECRET_KEY is required");
  const trimmed = raw.trim();
  const candidates = [
    Buffer.from(trimmed, "base64"),
    /^[a-f0-9]{64}$/i.test(trimmed) ? Buffer.from(trimmed, "hex") : Buffer.alloc(0),
    Buffer.from(trimmed, "utf8"),
  ];
  const key = candidates.find((candidate) => candidate.length === 32);
  if (!key) {
    throw new Error("OPERANT_SECRET_KEY must decode to exactly 32 bytes (base64, hex, or raw 32-byte string)");
  }
  return key;
}

export function encryptSecret(plaintext: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, iv.toString("base64"), tag.toString("base64"), ciphertext.toString("base64")].join(":");
}

export function decryptSecret(envelope: string, key: Buffer): string {
  const [version, ivB64, tagB64, ciphertextB64] = envelope.split(":");
  if (version !== PREFIX || !ivB64 || !tagB64 || !ciphertextB64) {
    throw new Error("Unsupported encrypted secret envelope");
  }
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const plaintext = Buffer.concat([decipher.update(Buffer.from(ciphertextB64, "base64")), decipher.final()]);
  return plaintext.toString("utf8");
}
