const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const ALPHABET_MAP: Record<string, number> = {};
for (let i = 0; i < ALPHABET.length; i++) {
  ALPHABET_MAP[ALPHABET[i]] = i;
}

function sha256(data: Uint8Array): Uint8Array {
  try {
    const nodeCrypto = require('crypto');
    return new Uint8Array(nodeCrypto.createHash('sha256').update(data).digest());
  } catch {
    throw new Error('SHA-256 not available');
  }
}

function doubleSha256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

export function encode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  if (bytes.length === 0) return '';

  let leadingZeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    leadingZeros++;
  }

  const digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] * 256;
      digits[j] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  let result = ALPHABET[0].repeat(leadingZeros);
  for (let i = digits.length - 1; i >= 0; i--) {
    result += ALPHABET[digits[i]];
  }

  return result;
}

export function decode(encoded: string): Uint8Array {
  if (encoded.length === 0) return new Uint8Array(0);

  let leadingOnes = 0;
  for (let i = 0; i < encoded.length && encoded[i] === ALPHABET[0]; i++) {
    leadingOnes++;
  }

  const bytes = [0];
  for (let i = 0; i < encoded.length; i++) {
    const digit = ALPHABET_MAP[encoded[i]];
    if (digit === undefined) {
      throw new Error(`Invalid character at position ${i}`);
    }
    let carry = digit;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
    while (carry > 0) {
      bytes.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  const result = new Uint8Array(leadingOnes + bytes.length);
  result.set(bytes.reverse(), leadingOnes);
  return result;
}

export function encodeChecked(data: Uint8Array): string {
  const hash = doubleSha256(data);
  const checksum = hash.slice(0, 4);
  const combined = new Uint8Array(data.length + 4);
  combined.set(data, 0);
  combined.set(checksum, data.length);
  return encode(combined);
}

export function decodeChecked(encoded: string): Uint8Array {
  const decoded = decode(encoded);
  if (decoded.length < 4) {
    throw new Error('Invalid checksum: data too short');
  }
  const data = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);
  const hash = doubleSha256(data);
  const expected = hash.slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) {
      throw new Error('Invalid checksum');
    }
  }
  return data;
}
