# OAuth Proxy module worker 

[![Quality](https://img.shields.io/badge/quality-experiment-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

An Oauth Proxy module is part of a [Token Handler](https://curity.io/resources/learn/the-token-handler-pattern/) component, a lightweight backend component designed to securely deal with tokens in Single Page Applications. This repository provides a Cloudflare worker implementation of the module using Typescript. The module is responsible for obtaining an access token from an encrypted cookie and forwards the request to the upstream API with the token put in the `Authorization` header. If opaque (phantom) tokens are used, the worker performs token introspection to exchange the opaque token for a JWT.

## Getting Started

 You need [Wrangler](https://github.com/cloudflare/wrangler) at least in version 1.17. to work with this code. If you are not already familiar with the tool, then have a look at the [documentation](https://developers.cloudflare.com/workers/tooling/wrangler/).

### Running the Dev Environment

First make sure that proper configuration values are entered in the `wrangler.toml` file, then run `wrangler dev` to start the worker in the dev environment. Have a look at the [Token Handler end to end tutorial](https://curity.io/resources/learn/token-handler-spa-tutorial/) to learn how to set up the rest of the environment used by the Token Handler. That tutorial uses an nginx API gateway and must be tweaked to work with this worker. 

### Testing

`npm test` will run the test suite. Tests are written using [Jest](https://jestjs.io/).

## More Information

Please visit [curity.io](https://curity.io/) for more information about the Token Handler and the Curity Identity Server.
