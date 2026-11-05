
import {
  startRegistration,
  startAuthentication
} from '@simplewebauthn/browser';

const API_BASE = 'http://localhost:3000/api/auth/passkey';

function showMessage(message, isError = false) {
  const element = document.getElementById('passkey-message');

  if (element) {
    element.textContent = message;
    element.style.display = 'block';
    element.style.color = isError ? '#f87171' : '#6ee7b7';
  }
}

function getEmail() {
  const email = document.getElementById('passkey-email')?.value
    ?.trim()
    .toLowerCase();

  if (!email) {
    throw new Error('Please enter your email address.');
  }

  return email;
}

async function post(endpoint, body) {
  const response = await fetch(`${API_BASE}/${endpoint}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || 'The request failed.');
  }

  return data;
}


function handleAuthenticationSuccess(data) {
  sessionStorage.setItem('token', data.token);
  sessionStorage.setItem('userEmail', data.email);

  document.getElementById('passkey-section').style.display = 'none';

  if (data.nextStep === 'encryption-setup') {
    document.getElementById('encryption-setup').style.display = 'block';
    showMessage('Passkey verified. Set up your file encryption.');
    return;
  }

  showMessage('Passkey login successful.');

  window.dispatchEvent(
    new CustomEvent('securedrive:authenticated', {
      detail: data
    })
  );
}


// --------------------------------------------------
// REGISTER WITH A PASSKEY
// --------------------------------------------------

async function registerWithPasskey() {
  try {
    showMessage('Starting passkey registration...');

    const email = getEmail();

    // 1. Ask backend for registration options and challenge ID.
    const optionsData = await post('register/options', { email });

    // 2. Ask the browser/authenticator to create a passkey.
    const registrationResponse = await startRegistration({
      optionsJSON: optionsData.options
    });

    // 3. Send the authenticator response and challenge ID to backend.
    const result = await post('register/verify', {
      email,
      response: registrationResponse,
      challengeId: optionsData.challengeId
    });

    handleAuthenticationSuccess(result);

  } catch (error) {
    console.error('Passkey registration error:', error);
    showMessage(error.message || 'Passkey registration failed.', true);
  }
}

// --------------------------------------------------
// LOGIN WITH A PASSKEY
// --------------------------------------------------

async function loginWithPasskey() {
  try {
    showMessage('Starting passkey login...');

    const email = getEmail();

    // 1. Ask backend for authentication options and challenge ID.
    const optionsData = await post('login/options', { email });

    // 2. Ask the authenticator to verify the user.
    const authenticationResponse = await startAuthentication({
      optionsJSON: optionsData.options
    });

    // 3. Send the authenticator response and challenge ID to backend.
    const result = await post('login/verify', {
      email,
      response: authenticationResponse,
      challengeId: optionsData.challengeId
    });

    handleAuthenticationSuccess(result);

  } catch (error) {
    console.error('Passkey login error:', error);
    showMessage(error.message || 'Passkey login failed.', true);
  }
}

// Connect the functions to the buttons in the HTML.
document.addEventListener('DOMContentLoaded', () => {
  document
    .getElementById('passkey-register-btn')
    ?.addEventListener('click', registerWithPasskey);

  document
    .getElementById('passkey-login-btn')
    ?.addEventListener('click', loginWithPasskey);
});
