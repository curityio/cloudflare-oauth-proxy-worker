import { handleRequest } from './handler'
import Configuration from "./configuration";

addEventListener('fetch', (event) => {
  const config = new Configuration(
    TRUSTED_WEB_ORIGINS,
    COOKIE_NAME_PREFIX,
    ENCRYPTION_KEY
)
  event.respondWith(handleRequest(event.request, config, fetch))
})
