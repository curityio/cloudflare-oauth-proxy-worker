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

import { handleRequest } from '../src/handler'
import makeServiceWorkerEnv from 'service-worker-mock'
import Configuration from '../src/configuration'
import encryptCookie from './cookieEncrypter'
import { serialize } from 'cookie'

declare let global: never

describe('OAuth Proxy tests', () => {
  const configuration = new Configuration(
    'https://example.com',
    'example',
    'cc26d51be30dd69f11369c6a7af214ef5fce70a6f6ef19f02ab55d4cff4bce5d',
    false,
    'https://login.example.com/token',
    'client',
    'secret',
  )

  const configWithPhantomTokenEnabled = new Configuration(
    configuration.trustedOriginsString,
    configuration.cookieNamePrefix,
    configuration.encryptionKey,
    true,
    configuration.introspectionURL,
    configuration.clientID,
    configuration.clientSecret,
  )

  const fetchOk = () => Promise.resolve(new Response('', { status: 200 }))

  beforeEach(() => {
    Object.assign(global, makeServiceWorkerEnv())
    jest.resetModules()
  })

  test('should pass OPTIONS without any checks', async () => {
    const result = await handleRequest(
      new Request('/', { method: 'OPTIONS' }),
      configuration,
      fetchOk,
    )
    expect(result.status).toEqual(200)
  })

  test('should pass requests with Bearer token without any modifications', async () => {
    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: { Authorization: 'Bearer access_token' },
      }),
      configuration,
      fetchOk,
    )
    expect(result.status).toEqual(200)
  })

  test('request from untrusted origin should return a 401 response', async () => {
    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: { Origin: 'https://malicious.site' },
      }),
      configuration,
      fetchOk,
    )
    expect(result.status).toEqual(401)
  })

  const dataChangingMethods = ['POST', 'PUT', 'PATCH', 'DELETE']

  test.each(dataChangingMethods)(
    'Data changing %p request without CSRF cookie should return 401 response',
    async (method) => {
      const result = await handleRequest(
        new Request('/', {
          method: method,
          headers: { Origin: configuration.trustedOrigins[0] },
        }),
        configuration,
        fetchOk,
      )
      expect(result.status).toEqual(401)
    },
  )

  test.each(dataChangingMethods)(
    'Data changing %p request with invalid CSRF cookie should return 401 response',
    async (method) => {
      const result = await handleRequest(
        new Request('/', {
          method: method,
          headers: {
            Origin: configuration.trustedOrigins[0],
            Cookie: serialize(
              configuration.cookieNamePrefix + '-csrf',
              'invalid',
            ),
          },
        }),
        configuration,
        fetchOk,
      )
      expect(result.status).toEqual(401)
    },
  )

  test.each(dataChangingMethods)(
    'Data changing %p request with a a valid CSRF cookie should return a 200 response',
    async (method) => {
      const csrfToken = 'abcdef'
      const csrfCookie = encryptCookie(csrfToken, configuration.encryptionKey)
      const csrfHeaderName = 'x-' + configuration.cookieNamePrefix + '-csrf'
      const headers = new Headers({
        Origin: configuration.trustedOrigins[0],
        Cookie: [
          serialize(configuration.cookieNamePrefix + '-csrf', csrfCookie),
          serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('token', configuration.encryptionKey),
          ),
        ].join('; '),
      })
      headers.set(csrfHeaderName, csrfToken)

      const result = await handleRequest(
        new Request('/', {
          method: method,
          headers: headers,
        }),
        configuration,
        fetchOk,
      )
      expect(result.status).toEqual(200)
    },
  )

  test('Request without an access token cookie should return a 401 response', async () => {
    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
        },
      }),
      configuration,
      fetchOk,
    )

    expect(result.status).toEqual(401)
  })

  test('Request with invalid access token cookie should return a 401 response', async () => {
    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(configuration.cookieNamePrefix + '-at', 'invalid'),
        },
      }),
      configuration,
      fetchOk,
    )

    expect(result.status).toEqual(401)
  })

  test('Request with a valid access token cookie should return a 200 and forward the token to the API', async () => {
    const fetch = (request: Request) => {
      const authorizationHeader = request.headers.get('Authorization')
      expect(authorizationHeader).toEqual('Bearer access_token')
      return Promise.resolve(new Response('', { status: 200 }))
    }

    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('access_token', configuration.encryptionKey),
          ),
        },
      }),
      configuration,
      fetch,
    )

    expect(result.status).toEqual(200)
  })

  test('When phantom-token option enabled, should return 503 when Authorization Server call returns a 5xx error', async () => {
    const fetch = () => Promise.resolve(new Response('', { status: 500 }))

    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('access_token', configuration.encryptionKey),
          ),
        },
      }),
      configWithPhantomTokenEnabled,
      fetch,
    )

    expect(result.status).toEqual(503)
  })

  test('When phantom-token option enabled, should return 503 when Authorization Server call fails', async () => {
    const fetch = () => {
      throw new Error('Connection to Authorization Server failed')
    }

    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('access_token', configuration.encryptionKey),
          ),
        },
      }),
      configWithPhantomTokenEnabled,
      fetch,
    )

    expect(result.status).toEqual(503)
  })

  test('When phantom-token option enabled, should return 401 when token expired', async () => {
    const fetch = () => Promise.resolve(new Response('', { status: 204 }))

    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('access_token', configuration.encryptionKey),
          ),
        },
      }),
      configWithPhantomTokenEnabled,
      fetch,
    )

    expect(result.status).toEqual(401)
  })

  test('When phantom-token option enabled, an introspection request should be performed', async () => {
    const fetch = (request: Request) => {
      if (request.url.endsWith('/token')) {
        const acceptHeader = request.headers.get('Accept')
        expect(acceptHeader).toEqual('application/jwt')
        return Promise.resolve(new Response('jwtToken', { status: 200 }))
      } else {
        const authorizationHeader = request.headers.get('Authorization')
        expect(authorizationHeader).toEqual('Bearer jwtToken')
        return Promise.resolve(new Response('', { status: 200 }))
      }
    }

    const result = await handleRequest(
      new Request('/', {
        method: 'GET',
        headers: {
          Origin: configuration.trustedOrigins[0],
          Cookie: serialize(
            configuration.cookieNamePrefix + '-at',
            encryptCookie('access_token', configuration.encryptionKey),
          ),
        },
      }),
      configWithPhantomTokenEnabled,
      fetch,
    )

    expect(result.status).toEqual(200)
  })
})
