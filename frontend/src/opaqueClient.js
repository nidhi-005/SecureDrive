import * as opaque from '@serenity-kit/opaque';

async function ensureOpaqueReady() {
  await opaque.ready;
}

export async function opaqueRegistrationStart(password) {
  await ensureOpaqueReady();
  return opaque.client.startRegistration({ password });
}

export async function opaqueRegistrationFinish({
  password,
  clientRegistrationState,
  registrationResponse
}) {
  await ensureOpaqueReady();
  return opaque.client.finishRegistration({
    password,
    clientRegistrationState,
    registrationResponse
  });
}

export async function opaqueLoginStart(password) {
  await ensureOpaqueReady();
  return opaque.client.startLogin({ password });
}

export async function opaqueLoginFinish({
  password,
  clientLoginState,
  loginResponse
}) {
  await ensureOpaqueReady();
  return opaque.client.finishLogin({
    clientLoginState,
    loginResponse,
    password
  });
}

export const opaqueClient = opaque.client;
export const opaqueServer = opaque.server;
