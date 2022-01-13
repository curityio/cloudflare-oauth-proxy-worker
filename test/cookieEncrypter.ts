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

import crypto, { CipherKey } from 'crypto'

export default function encryptCookie(
  value: string,
  encryptionKeyHex: string,
): string {
  const ivBytes = crypto.randomBytes(12)
  const encryptionKeyBytes = Buffer.from(encryptionKeyHex, 'hex')

  return encrypt(value, encryptionKeyBytes, ivBytes)
}

function encrypt(
  payloadText: string,
  encryptionKeyBytes: CipherKey,
  ivBytes: Buffer,
) {
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    encryptionKeyBytes,
    ivBytes,
  )

  const plaintextBytes = Buffer.from(payloadText, 'ascii')
  const ciphertextBytes = Buffer.concat([
    cipher.update(plaintextBytes),
    cipher.final(),
  ])
  const tagBytes = cipher.getAuthTag()

  return (
    ivBytes.toString('hex') +
    ciphertextBytes.toString('hex') +
    tagBytes.toString('hex')
  )
}
