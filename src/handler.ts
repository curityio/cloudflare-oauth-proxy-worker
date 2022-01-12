import Configuration from "./configuration"
import decryptCookie from "./cookieDecrypter"
import { parse } from "cookie"

export async function handleRequest(request: Request, config: Configuration, fetch: (request: Request) => Promise<Response>): Promise<Response> {

  // Ignore pre-flight requests from browser clients
  if (request.method == "OPTIONS") {
    return fetch(request)
  }

  // If there is already a bearer token, eg for mobile clients, return immediately
  // Note that the target API must always digitally verify the JWT access token
  const authorizationHeader = request.headers.get("Authorization")
  if (authorizationHeader && authorizationHeader.startsWith("Bearer ")) {
    return fetch(request)
  }

  // For cookie requests, verify the web origin in line with OWASP CSRF best practices
  const originFromHeader = request.headers.get("Origin") || ""

  if (config.trustedOrigins.length) {
    if (!config.trustedOrigins.includes(originFromHeader)) {
      console.warn("The %s request to %s was from an untrusted web origin: %s. Trusted origins: %s", request.method, request.url, originFromHeader, config.trustedOriginsString)
      return new Response(JSON.stringify({ message: "The request failed cookie authorization", code: "unauthorized" }), {
        status: 401,
        statusText: 'Unauthorized'
      })
    }
  }

  const cookies = parse(request.headers.get("Cookie") || "")
  const dataChangingMethods = ['POST', 'PUT', 'DELETE', 'PATCH']

  // For data changing requests do double submit cookie verification in line with OWASP CSRF best practices
  if (dataChangingMethods.includes(request.method)) {
      const csrfCookieName = config.cookieNamePrefix + "-csrf"
      const csrfEncryptedCookie = cookies[csrfCookieName]

      if (!csrfEncryptedCookie) {
        console.warn("No CSRF cookie was sent with the %s request to %s", request.method, request.url)
        return unauthorizedResponse(config.trustedOrigins, originFromHeader)
      }

      let csrfTokenFromCookie = ""

      try {
        csrfTokenFromCookie = decryptCookie(csrfEncryptedCookie, config.encryptionKey)
      } catch (error) {
        console.warn("Error decrypting CSRF cookie %s during %s request to %s ", csrfEncryptedCookie, request.method, request.url)
        return unauthorizedResponse(config.trustedOrigins, originFromHeader)
      }

      const csrfTokenFromHeader = request.headers.get("x-" + csrfCookieName)
      if (csrfTokenFromHeader !== csrfTokenFromCookie) {
        console.warn("Invalid or missing CSRF request header %s during %s request to %. CSRF token from cookie: %s",
            csrfTokenFromHeader, request.method, request.url, csrfTokenFromCookie)
        return unauthorizedResponse(config.trustedOrigins, originFromHeader)
      }
  }

    // Next verify that the main cookie was received and get the access token
    const accessTokenEncryptedCookie = cookies[config.cookieNamePrefix + "-at"]
    if (!accessTokenEncryptedCookie) {
        console.warn("No access token cookie was sent with the %s request to %s", request.method, request.url)
        return unauthorizedResponse(config.trustedOrigins, originFromHeader)
    }

    // Decrypt the access token cookie, which is encrypted using AES256
    try {
        const accessToken = decryptCookie(accessTokenEncryptedCookie, config.encryptionKey)

        // Forward the access token to the next plugin or the target API
        const requestToForward = new Request(request)
        requestToForward.headers.set("Authorization", "Bearer " + accessToken)
        return fetch(requestToForward)
    } catch (error) {
        console.warn("Error decrypting access token cookie %s during %s request to %s", accessTokenEncryptedCookie, request.method, request.url)
        return unauthorizedResponse(config.trustedOrigins, originFromHeader)
    }
}

const unauthorizedResponse = (trustedOrigins: string[], originHeader: string) => {
  const headers = new Headers({
    'Content-Type': 'application/json'
  })

  if (trustedOrigins.length) {
      if (trustedOrigins.includes(originHeader)) {
          headers.set('Access-Control-Allow-Origin', originHeader)
          headers.set('Access-Control-Allow-Credentials', 'true')
      }
  }
  return new Response(
      JSON.stringify({ message: 'The request failed cookie authorization', code: 'unauthorized'}), {
        status: 401,
        headers
      }
  )
}
