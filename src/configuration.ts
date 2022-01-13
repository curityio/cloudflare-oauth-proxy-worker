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

export default class Configuration {
  private readonly _trustedOrigins: string[]
  private readonly _trustedOriginsString: string
  private readonly _cookieNamePrefix: string
  private readonly _encryptionKey: string
  private readonly _phantomToken: boolean
  private readonly _introspectionURL: string
  private readonly _clientID: string
  private readonly _clientSecret: string

  constructor(
    trustedOrigins: string,
    cookieNamePrefix: string,
    encryptionKey: string,
    phantomToken: boolean,
    introspectionURL: string,
    clientID: string,
    clientSecret: string,
  ) {
    this._trustedOriginsString = trustedOrigins
    this._trustedOrigins = trustedOrigins.split(',')
    this._cookieNamePrefix = cookieNamePrefix
    this._encryptionKey = encryptionKey
    this._phantomToken = phantomToken
    this._introspectionURL = introspectionURL
    this._clientID = clientID
    this._clientSecret = clientSecret
  }

  get trustedOrigins(): string[] {
    return this._trustedOrigins
  }

  get trustedOriginsString(): string {
    return this._trustedOriginsString
  }

  get cookieNamePrefix(): string {
    return this._cookieNamePrefix
  }

  get encryptionKey(): string {
    return this._encryptionKey
  }

  get phantomToken(): boolean {
    return this._phantomToken
  }

  get introspectionURL(): string {
    return this._introspectionURL
  }

  get clientID(): string {
    return this._clientID
  }

  get clientSecret(): string {
    return this._clientSecret
  }
}
