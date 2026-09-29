import { constantTimeEquals } from './api-key';

const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeRecoveryCode(raw: string): string {
  return String(raw || '')
    .toUpperCase()
    .replace(/[^A-Z2-7]/g, '');
}

export function createRecoveryCode(): string {
  // The 32-character alphabet divides 256 exactly, so every random byte maps without bias.
  return Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    (byte) => RECOVERY_ALPHABET[byte % RECOVERY_ALPHABET.length],
  )
    .join('')
    .replace(/(.{4})/g, '$1 ')
    .trim();
}

export function recoveryCodeEquals(input: string, storedCode: string | null | undefined): boolean {
  return !!storedCode && constantTimeEquals(normalizeRecoveryCode(input), normalizeRecoveryCode(storedCode));
}
