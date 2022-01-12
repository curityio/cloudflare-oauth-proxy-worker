import crypto, { CipherKey } from 'crypto';

export default function encryptCookie(value: string, encryptionKeyHex: string): string {
    const ivBytes = crypto.randomBytes(12)
    const encryptionKeyBytes = Buffer.from(encryptionKeyHex, 'hex')

    return encrypt(value, encryptionKeyBytes, ivBytes)
}

function encrypt(payloadText: string, encryptionKeyBytes: CipherKey, ivBytes: Buffer) {

    const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKeyBytes, ivBytes);

    const plaintextBytes = Buffer.from(payloadText, 'ascii');
    const ciphertextBytes = Buffer.concat([cipher.update(plaintextBytes), cipher.final()]);
    const tagBytes = cipher.getAuthTag();

    return ivBytes.toString('hex') + ciphertextBytes.toString('hex') + tagBytes.toString('hex');
}
