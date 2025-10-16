// Base64URL helpers
const b64uToBuf = (b64u) =>
  Uint8Array.from(atob(b64u.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bufToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function mapCreateOptions(opts) {
  const o = JSON.parse(JSON.stringify(opts));
  o.publicKey.challenge = b64uToBuf(o.publicKey.challenge);
  if (o.publicKey.user && o.publicKey.user.id) o.publicKey.user.id = b64uToBuf(o.publicKey.user.id);
  if (o.publicKey.excludeCredentials) {
    o.publicKey.excludeCredentials = o.publicKey.excludeCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  }
  return o;
}

function mapGetOptions(opts) {
  const o = JSON.parse(JSON.stringify(opts));
  o.publicKey.challenge = b64uToBuf(o.publicKey.challenge);
  if (o.publicKey.allowCredentials) {
    o.publicKey.allowCredentials = o.publicKey.allowCredentials.map((c) => ({ ...c, id: b64uToBuf(c.id) }));
  }
  return o;
}

async function webauthnCreate(options) {
  const mapped = mapCreateOptions(options);
  const cred = await navigator.credentials.create(mapped);
  return {
    id: cred.id,
    type: cred.type,
    rawId: bufToB64u(cred.rawId),
    response: {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    },
    transports: cred.response.getTransports ? cred.response.getTransports() : [],
  };
}

async function webauthnGet(options) {
  const mapped = mapGetOptions(options);
  const assertion = await navigator.credentials.get(mapped);
  return {
    id: assertion.id,
    type: assertion.type,
    rawId: bufToB64u(assertion.rawId),
    response: {
      authenticatorData: bufToB64u(assertion.response.authenticatorData),
      clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
      signature: bufToB64u(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
    },
  };
}
