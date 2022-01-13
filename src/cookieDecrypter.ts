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

import crypto from 'crypto'

const GCM_IV_SIZE = 12
const GCM_TAG_SIZE = 16

export default function decryptCookie(
  cookieValue: string,
  encryptionKeyHex: string,
): string {
  const encryptionKeyBytes = Buffer.from(encryptionKeyHex, 'hex')
  return decrypt(cookieValue, encryptionKeyBytes)
}

function decrypt(payloadHex: string, encryptionKeyBytes: Buffer): string {
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

  const ivBytes = Buffer.from(ivHex, 'hex')
  const ciphertextBytes = Buffer.from(ciphertextHex, 'hex')
  const tagBytes = Buffer.from(tagHex, 'hex')

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    encryptionKeyBytes,
    ivBytes,
  )
  decipher.setAuthTag(tagBytes)
  const plaintextBytes = Buffer.concat([
    decipher.update(ciphertextBytes),
    decipher.final(),
  ])

  return plaintextBytes.toString('ascii')
}
