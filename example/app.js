import WebAuthn from 'ti.webauthn';

WebAuthn.addEventListener('error', ({ error }) => {
  // Handle error
  console.error(error);
});

WebAuthn.addEventListener('verification', event => {
  // Handle verification (different properties are set based on the credential type)
  console.log(event.credentialType);
});

const window = Ti.UI.createWindow();

window.addEventListener('open', () => {
	// Register a new device
	WebAuthn.register({
		challenge: '<base-64-encoded-challenge-from-server>',
		userId: '<user-id-from-server',
		userName: '<user-name-from-server>',
		relyingParty: '<relying-party-from-server>'
	});

	// OR: Login an existing device
	//
	// WebAuthn.login({
	// 	 challenge: '<base-64-encoded-server-challenge>',
	//   relyingParty: '<relying-party-from-server>'
	// });
});

window.open();