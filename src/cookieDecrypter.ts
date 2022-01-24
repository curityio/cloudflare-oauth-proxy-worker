/*
 *  Copyright 2022 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

const VERSION_SIZE = 1;
const GCM_IV_SIZE = 12;
const GCM_TAG_SIZE = 16;
const CURRENT_VERSION = 1;

export default async function decryptCookie(
  payloadBase64UrlEncoded: string,
  encryptionKeyHex: string,
): Promise<string> {
  const payloadBytes = base64DecodeURL(payloadBase64UrlEncoded)

  const minSize = (VERSION_SIZE + GCM_IV_SIZE + 1 + GCM_TAG_SIZE)
  if (payloadBytes.length < minSize) {
    throw new Error('The received payload is invalid and cannot be parsed')
  }

  const version = payloadBytes[0]
  if (version !== CURRENT_VERSION) {
    throw new Error('The received cookie has an invalid format')
  }

  let offset = VERSION_SIZE

  const ivBytes = payloadBytes.slice(offset, offset + GCM_IV_SIZE)
  offset += GCM_IV_SIZE
  const ciphertextAndTagBytes = payloadBytes.slice(offset)

  const aesKey = await crypto.subtle.importKey(
      'raw',
      hexToBytes(encryptionKeyHex),
      'AES-GCM',
      true,
      ['decrypt'],
  )

  const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        tagLength: GCM_TAG_SIZE * 8, // length in bits
      },
      aesKey,
      ciphertextAndTagBytes,
  )

  const decoder = new TextDecoder()
  return decoder.decode(decrypted)
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i !== bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes
}

function base64DecodeURL(b64urlstring: string): Uint8Array {
  return new Uint8Array(atob(b64urlstring.replace(/-/g, '+').replace(/_/g, '/')).split('').map(val => {
    return val.charCodeAt(0);
  }));
}
