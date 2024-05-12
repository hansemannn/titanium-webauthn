# Titanium WebAuthn

Native support for the WebAuthn authentication strategy (also called "Passkeys") in Titanium!

<img src="./.github/webauthn-logo.png" height="80" alt="WebAuthn Logo" /> <img src="./.github/passkeys-logo.png" height="80" alt="Passkeys Logo" />

## Requirements

- [x] iOS 15+ (Android is not implemented, yet)
- [x] A valid server instance that is ready for Webauthn, e.g. Auth0 or Passport.js

## Example

```js
import WebAuthn from 'ti.webauthn';

WebAuthn.addEventListener('error', ({ error }) => {
  // Handle error
});

WebAuthn.addEventListener('verification', ({ credential }) => {
  // Handle verification
  console.log(credential);
});

WebAuthn.addEventListener('registration', ({ credential }) => {
  // Handle registration
  console.log(credential);
});

// Register a new device
WebAuthn.register({
  challenge: '<base-64-encoded-server-challenge>',
  userId: '123',
  userName: 'Hans',
  relyingParty: 'example.com'
});

// Login an existing device
WebAuthn.login({
  challenge: '<base-64-encoded-server-challenge>',
  relyingParty: 'example.com'
});

## Author

Hans Knöchel

## License

MIT
