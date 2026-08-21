import assert from 'node:assert/strict';
import test from 'node:test';

import * as opaque from '@serenity-kit/opaque';

import {
  opaqueLoginFinish,
  opaqueLoginStart,
  opaqueRegistrationFinish,
  opaqueRegistrationStart
} from './src/opaqueClient.js';

test('opaque client wrapper performs a real registration and login flow', async () => {
  const password = 'CorrectHorseBatteryStaple!';

  await opaque.ready;

  // Generate a valid OPAQUE server setup.
  const serverSetup = opaque.server.createSetup();

  const registrationStart = await opaqueRegistrationStart(password);

  assert.ok(registrationStart.clientRegistrationState);
  assert.ok(registrationStart.registrationRequest);

  const { registrationResponse } =
    opaque.server.createRegistrationResponse({
      serverSetup,
      userIdentifier: 'alice@example.com',
      registrationRequest: registrationStart.registrationRequest
    });

  const registrationFinish = await opaqueRegistrationFinish({
    password,
    clientRegistrationState: registrationStart.clientRegistrationState,
    registrationResponse
  });

  assert.ok(registrationFinish.registrationRecord);
  assert.ok(registrationFinish.exportKey);

  const loginStart = await opaqueLoginStart(password);

  assert.ok(loginStart.clientLoginState);
  assert.ok(loginStart.startLoginRequest);

  const { loginResponse, serverLoginState } =
    opaque.server.startLogin({
      serverSetup,
      userIdentifier: 'alice@example.com',
      registrationRecord: registrationFinish.registrationRecord,
      startLoginRequest: loginStart.startLoginRequest
    });

  const loginFinish = await opaqueLoginFinish({
    password,
    clientLoginState: loginStart.clientLoginState,
    loginResponse
  });

  assert.ok(loginFinish);
  assert.ok(loginFinish.finishLoginRequest);
  assert.ok(loginFinish.sessionKey);

  const finalServerAuth =
    opaque.server.finishLogin({
      finishLoginRequest: loginFinish.finishLoginRequest,
      serverLoginState
    });

  assert.ok(finalServerAuth.sessionKey);
});