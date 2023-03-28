# cloudflare-access-forwardauth
A ForwardAuth implementation based on Cloudflare Access.

## supported features

- [x] validates Access JWT from Cloudflare Access header (`Cf-Access-Jwt-Assertion`)
- [x] sets custom claim data (specified in `custom` claim) as response headers
  (`X-Custom-Claim-Key`)
- [ ] handles claim data other than strings (concat array values with commas, etc)
- [x] refreshes JWKS data periodically at runtime
- [ ] refresh JWKS inline during JWT validation if current JWKS data is out-of-date
