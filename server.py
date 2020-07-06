from typing import Dict
import re
import secrets

from flask import Flask, jsonify, render_template, request, session
import webauthn

app = Flask(__name__)
app.secret_key = 'be291b7e67da5a6007b052bd98357f9f'

RELYING_PARTY_ID = 'localhost'
RELYING_PARTY_NAME = 'MinimalWebAuthnDemo'
ICON_URL = 'https://upload.wikimedia.org/wikipedia/commons/thumb/2/2f/Google_2015_logo.svg/200px-Google_2015_logo.svg.png'
ORIGIN = 'http://localhost:5000'

# TODO: session protection, like in https://flask-login.readthedocs.io/en/latest/#session-protection


USERS: Dict[str, str] = {}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register_start', methods=['POST'])
def register_start():
    username = request.json.get('username')
    assert isinstance(username, str) and re.match(r"^[a-zA-Z0-9]{1,32}$", username), username

    challenge = secrets.token_urlsafe(32)
    user_id = secrets.token_urlsafe(20)

    session['challenge'] = challenge
    session['user_id'] = user_id
    session['username'] = username

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge=challenge,
        rp_name=RELYING_PARTY_NAME,
        rp_id=RELYING_PARTY_ID,
        user_id=user_id,
        username=username,
        display_name=username,
        icon_url=ICON_URL,
    )
    return jsonify(status='success', options=make_credential_options.registration_dict)


@app.route('/register', methods=['POST'])
def register():
    challenge = session['challenge']
    user_id = session['user_id']
    username = session['username']

    client_data, att_obj, registration_client_extensions = request.json.get('clientData'), request.json.get('attObj'), request.json.get('registrationClientExtensions')
    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        rp_id=RELYING_PARTY_ID,
        origin=ORIGIN,
        registration_response={'clientData': client_data, 'attObj': att_obj, 'registrationClientExtensions': registration_client_extensions},
        challenge=challenge,
        trusted_attestation_cert_required=True,
    )
    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return jsonify(status='failure', error=str(e))

    if any(u['credential_id'] == webauthn_credential.credential_id for u in USERS.values()):
        return jsonify(status='failure', error='Credential ID already in use')
    if username in USERS:
        return jsonify(status='failure', error='Username already in use')

    user = {
        'id': user_id,
        'username': username,
        'credential_id': webauthn_credential.credential_id.decode('utf8'),
        'public_key': webauthn_credential.public_key.decode('utf8'),
    }
    USERS[username] = user
    return jsonify(status='success', user=user)


@app.route('/login_start', methods=['POST'])
def login_start():
    username = request.json.get('username')
    if username not in USERS:
        return jsonify(status='failure', error='User with given username not found')

    challenge = secrets.token_urlsafe(32)
    session['challenge'] = challenge

    user = USERS[username]
    user_id, username, credential_id, public_key = user['id'], user['username'], user['credential_id'], user['public_key']
    webauthn_user = webauthn.WebAuthnUser(user_id=user_id, username=username, display_name=username, icon_url=ICON_URL, credential_id=credential_id, public_key=public_key, sign_count=0, rp_id=RELYING_PARTY_ID)
    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(webauthn_user, challenge)
    return jsonify(status='success', options=webauthn_assertion_options.assertion_dict)


@app.route('/login', methods=['POST'])
def login():
    challenge = session.get('challenge')
    credential_id = request.json.get('id')
    user_handle = request.json.get('userHandle')
    client_data = request.json.get('clientData')
    auth_data = request.json.get('authData')
    signature = request.json.get('signature')
    assertion_client_extensions = request.json.get('assertionClientExtensions')

    user = next((u for u in USERS.values() if u['credential_id'] == credential_id), None)
    if user is None:
        return jsonify(status='failure', error='User with given credential ID not found')

    user_id, username, credential_id, public_key = user['id'], user['username'], user['credential_id'], user['public_key']
    webauthn_user = webauthn.WebAuthnUser(user_id=user_id, username=username, display_name=username, icon_url=ICON_URL, credential_id=credential_id, public_key=public_key, sign_count=0, rp_id=RELYING_PARTY_ID)
    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user=webauthn_user,
        assertion_response={'id': credential_id, 'userHandle': user_handle, 'clientData': client_data, 'authData': auth_data, 'signature': signature, 'assertionClientExtensions': assertion_client_extensions},
        challenge=challenge,
        origin=ORIGIN,
    )
    try:
        webauthn_assertion_response.verify()
    except Exception as e:
        return jsonify(status='failure', error=str(e))

    return jsonify(status='success', user=user)
