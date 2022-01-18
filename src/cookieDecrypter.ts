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

const GCM_IV_SIZE = 12
const GCM_TAG_SIZE = 16

export default async function decryptCookie(
  payloadHex: string,
  encryptionKeyHex: string,
): Promise<string> {
  const minSize = (GCM_IV_SIZE + 1 + GCM_TAG_SIZE) * 2
  if (payloadHex.length < minSize) {
    throw new Error('The received payload is invalid and cannot be parsed')
  }

  const ivHex = payloadHex.substring(0, GCM_IV_SIZE * 2)
  const ciphertextHex = payloadHex.substring(
    GCM_IV_SIZE * 2,
    payloadHex.length - GCM_TAG_SIZE * 2,
  )
  const tagHex = payloadHex.substring(payloadHex.length - GCM_TAG_SIZE * 2)

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
      iv: hexToBytes(ivHex),
      tagLength: GCM_TAG_SIZE * 8,
    },
    aesKey,
    hexToBytes(ciphertextHex + tagHex),
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
