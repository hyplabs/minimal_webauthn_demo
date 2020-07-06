Minimal WebAuthn Demo
=====================

A small but complete registration/login flow demo using WebAuthentication. No database, no flask-login, just plain [Flask](flask.palletsprojects.com/) and [PyWebAuthn](https://github.com/duo-labs/py_webauthn). Tested with a Yubikey 4 and Firefox.

Quickstart:

```bash
pip install -r requirements.txt
FLASK_APP=server.py flask run
# go to http://localhost:5000/ to view the login/register page
```

Heavily based on the [PyWebAuthn Flask Demo](https://github.com/duo-labs/py_webauthn/tree/master/flask_demo). I tried to use more conventional names such as "login" rather than "challenge/assert", to make things more readable.

Configuration
-------------

TODO: setting RELYING_PARTY_NAME, RELYING_PARTY_ID, etc

Device Attestation
------------------

[Attestation](https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Attestation_and_Assertion) is a process in which the authenticator tells the server its manufacturer and model, and proves to the server that it's a genuine instance of that model. This is typically done by the manufacturer, where they sign the authenticator's public key with the manufacturer's attestation certificate. The server can then verify that the authenticator is in fact what it says it is by checking the attestation against the manufacturer's attestation certificate. That means the server needs to have a copy of various attestation certificates from various manufacturers.

This demo only includes the Yubico device attestation certificate (`trusted_attestation_roots/yubico_u2f_device_attestation_ca.pem`, which I got from the [Yubico website](https://developers.yubico.com/U2F/yubico-u2f-ca-certs.txt)). That means only Yubico devices will be able to pass attestation (which happens during registration). To allow attestation for devices from other manufacturers, you can add more attestation certificates in `trusted_attestation_roots/` and they'll be picked up automatically. There are [more attestation certificates from various manufacturers in the PyWebAuthn Flask Demo](https://github.com/duo-labs/py_webauthn/tree/master/flask_demo/trusted_attestation_roots), or alternatively you can search online or ask the authenticator's manufacturer for a copy of their attestation certificate.

Optionally, you can also turn off attestation entirely by changing `trusted_attestation_cert_required=True` to `trusted_attestation_cert_required=False` in `server.py`.
