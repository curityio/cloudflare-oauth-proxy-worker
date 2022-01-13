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

import Configuration from './configuration'
import decryptCookie from './cookieDecrypter'
import { parse } from 'cookie'
import AuthorizationServerError from './AuthorizationServerError'

export async function handleRequest(
  request: Request,
  config: Configuration,
  fetch: (request: Request) => Promise<Response>,
): Promise<Response> {
  // Ignore pre-flight requests from browser clients
  if (request.method == 'OPTIONS') {
    return fetch(request)
  }

  // If there is already a bearer token, eg for mobile clients, return immediately
  // Note that the target API must always digitally verify the JWT access token
  const authorizationHeader = request.headers.get('Authorization')
  if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
    return fetch(request)
  }

  // For cookie requests, verify the web origin in line with OWASP CSRF best practices
  const originFromHeader = request.headers.get('Origin') || ''

  if (config.trustedOrigins.length) {
    if (!config.trustedOrigins.includes(originFromHeader)) {
      console.warn(
        'The %s request to %s was from an untrusted web origin: %s. Trusted origins: %s',
        request.method,
        request.url,
        originFromHeader,
        config.trustedOriginsString,
      )
      return new Response(
        JSON.stringify({
          message: 'The request failed cookie authorization',
          code: 'unauthorized',
        }),
        {
          status: 401,
          statusText: 'Unauthorized',
        },
      )
    }
  }

  const cookies = parse(request.headers.get('Cookie') || '')
  const dataChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH']

  // For data changing requests do double submit cookie verification in line with OWASP CSRF best practices
  if (dataChangingMethods.includes(request.method)) {
    const csrfCookieName = config.cookieNamePrefix + '-csrf'
    const csrfEncryptedCookie = cookies[csrfCookieName]

    if (!csrfEncryptedCookie) {
      console.warn(
        'No CSRF cookie was sent with the %s request to %s',
        request.method,
        request.url,
      )
      return unauthorizedResponse(config.trustedOrigins, originFromHeader)
    }

    let csrfTokenFromCookie = ''

    try {
      csrfTokenFromCookie = decryptCookie(
        csrfEncryptedCookie,
        config.encryptionKey,
      )
    } catch (error) {
      console.warn(
        'Error decrypting CSRF cookie %s during %s request to %s ',
        csrfEncryptedCookie,
        request.method,
        request.url,
      )
      return unauthorizedResponse(config.trustedOrigins, originFromHeader)
    }

    const csrfTokenFromHeader = request.headers.get('x-' + csrfCookieName)
    if (csrfTokenFromHeader !== csrfTokenFromCookie) {
      console.warn(
        'Invalid or missing CSRF request header %s during %s request to %. CSRF token from cookie: %s',
        csrfTokenFromHeader,
        request.method,
        request.url,
        csrfTokenFromCookie,
      )
      return unauthorizedResponse(config.trustedOrigins, originFromHeader)
    }
  }

  // Next verify that the main cookie was received and get the access token
  const accessTokenEncryptedCookie = cookies[config.cookieNamePrefix + '-at']
  if (!accessTokenEncryptedCookie) {
    console.warn(
      'No access token cookie was sent with the %s request to %s',
      request.method,
      request.url,
    )
    return unauthorizedResponse(config.trustedOrigins, originFromHeader)
  }

  // Decrypt the access token cookie, which is encrypted using AES256
  let requestToForward = null
  let accessToken: string | null

  try {
    accessToken = decryptCookie(
      accessTokenEncryptedCookie,
      config.encryptionKey,
    )
  } catch (error) {
    console.warn(
      'Error decrypting access token cookie %s during %s request to %s',
      accessTokenEncryptedCookie,
      request.method,
      request.url,
    )
    return unauthorizedResponse(config.trustedOrigins, originFromHeader)
  }

  if (config.phantomToken) {
    // Exchange phantom token for a JWT
    try {
      accessToken = await exchangePhantomToken(accessToken, config, fetch)
    } catch (error) {
      console.warn(
        'Error encountered when trying to exchange the Phantom Token during %s request to %s. Access token from cookie: %s',
        request.method,
        request.url,
        accessToken,
        error,
      )
      return badGatewayResponse(config.trustedOrigins, originFromHeader)
    }
  }

  if (!accessToken) {
    return unauthorizedResponse(config.trustedOrigins, originFromHeader)
  }

  // Prepare a request with a new token
  requestToForward = new Request(request)
  requestToForward.headers.set('Authorization', 'Bearer ' + accessToken)

  // Forward the access token to the target API
  if (requestToForward) {
    return fetch(requestToForward)
  }

  return unauthorizedResponse(config.trustedOrigins, originFromHeader)
}

const errorResponse = (
  statusCode: number,
  code: string,
  message: string,
  trustedOrigins: string[],
  originHeader: string,
) => {
  const headers = new Headers({
    'Content-Type': 'application/json',
  })

  if (trustedOrigins.length) {
    if (trustedOrigins.includes(originHeader)) {
      headers.set('Access-Control-Allow-Origin', originHeader)
      headers.set('Access-Control-Allow-Credentials', 'true')
    }
  }
  return new Response(JSON.stringify({ message, code }), {
    status: statusCode,
    headers,
  })
}

const unauthorizedResponse = (trustedOrigins: string[], originHeader: string) =>
  errorResponse(
    401,
    'unauthorized',
    'The request failed cookie authorization',
    trustedOrigins,
    originHeader,
  )

const badGatewayResponse = (trustedOrigins: string[], originHeader: string) =>
  errorResponse(
    503,
    'Bad Gateway',
    'Introspection request failed',
    trustedOrigins,
    originHeader,
  )

const exchangePhantomToken = async (
  accessToken: string,
  configuration: Configuration,
  fetch: (request: Request) => Promise<Response>,
): Promise<string | null> => {
  const credentials = configuration.clientID + ':' + configuration.clientSecret
  const base64Credentials = Buffer.from(credentials)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
  const introspectionRequest = new Request(configuration.introspectionURL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/jwt',
      Authorization: 'Basic ' + base64Credentials,
    },
    body: 'token=' + accessToken,
  })

  const introspectionResponse = await fetch(introspectionRequest)

  if (introspectionResponse.status == 204) {
    return null
  }

  if (introspectionResponse.status != 200) {
    throw new AuthorizationServerError()
  }

  return introspectionResponse.text()
}
