# OAuth Proxy module worker 

[![Quality](https://img.shields.io/badge/quality-experiment-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

An Oauth Proxy module is part of a [Token Handler](https://curity.io/resources/learn/the-token-handler-pattern/) component, a lightweight backend component designed to securely deal with tokens in Single Page Applications. This repository provides a Cloudflare worker implementation of the module using Typescript. The module is responsible for obtaining an access token from an encrypted cookie and forwards the request to the upstream API with the token put in the `Authorization` header. If opaque (phantom) tokens are used, the worker performs token introspection to exchange the opaque token for a JWT.

## Getting Started

 You need [Wrangler](https://github.com/cloudflare/wrangler) at least in version 1.17. to work with this code. If you are not already familiar with the tool, then have a look at the [documentation](https://developers.cloudflare.com/workers/tooling/wrangler/).

### Running the Dev Environment

First make sure that proper configuration values are entered in the `wrangler.toml` file, then run `wrangler dev` to start the worker in the dev environment. Have a look at the [SPA and Token Handler's Deployment](https://github.com/curityio/spa-using-token-handler) to learn how to set up the rest of the environment used by the Token Handler. That tutorial uses an nginx API gateway and must be tweaked to work with this worker. 

### Testing

`npm test` will run the test suite. Tests are written using [Jest](https://jestjs.io/).

## Configuration

The worker uses the following environment variables for configuration. These can be set in the `wrangler.toml` file or directly from the Cloudflare workers UI.

- `TRUSTED_WEB_ORIGINS` - a comma-separated list of trusted web origins. Requests coming from other origins will be rejected by the Proxy.
- `COOKIE_NAME_PREFIX` - the name prefix of the cookies used by the proxy.
- `ENCRYPTION_KEY` - a 256-bit encryption key represented as a 64-character hex string. The key is used to decrypt cookie values. You can use the following command to generate a secure key: `openssl rand 32 | xxd -p -c 64`
- `USE_PHANTOM_TOKEN` - a boolean informing the worker whether a phantom token is used. If true, then the worker will perform token introspection before calling the API.
- `INTROSPECTION_URL` - the URL of the introspection endpoint of the Authorization Server.
- `CLIENT_ID` - the ID of the client used to perform the introspection call.
- `CLIENT_SECRET` - the secret of the client used to perform the introspection call.

## More Information

Please visit [curity.io](https://curity.io/) for more information about the Token Handler and the Curity Identity Server.
