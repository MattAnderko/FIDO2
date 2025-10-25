// Base64URL helpers
const b64uToBuf = (b64u) =>
  Uint8Array.from(atob(b64u.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const bufToB64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

const withPublicKey = (opts) => {
  if (!opts) throw new Error('WebAuthn options payload missing.');
  return opts.publicKey ? opts : { publicKey: opts };
};

const ensureWebauthnSupport = () => {
  if (
    !navigator.credentials ||
    typeof navigator.credentials.create !== 'function' ||
    typeof navigator.credentials.get !== 'function'
  ) {
    throw new Error('WebAuthn navigator.credentials API unavailable (https or localhost required).');
  }
};

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
  const id = bufToB64u(cred.rawId);
  return {
    id,
    type: cred.type,
    rawId: id,
    response: {
      attestationObject: bufToB64u(cred.response.attestationObject),
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
    },
    transports: typeof cred.getTransports === 'function' ? cred.getTransports() : [],
    clientExtensionResults: typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {},
  };
}

async function webauthnGet(options) {
  const mapped = mapGetOptions(options);
  const assertion = await navigator.credentials.get(mapped);
  const id = bufToB64u(assertion.rawId);
  return {
    id,
    type: assertion.type,
    rawId: id,
    response: {
      authenticatorData: bufToB64u(assertion.response.authenticatorData),
      clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
      signature: bufToB64u(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : null,
    },
    clientExtensionResults:
      typeof assertion.getClientExtensionResults === 'function' ? assertion.getClientExtensionResults() : {},
  };
}

window.webauthn = {
  async createFromJson(optionsJson) {
    ensureWebauthnSupport();
    const options = withPublicKey(JSON.parse(optionsJson));
    const credential = await webauthnCreate(options);
    return JSON.stringify(credential);
  },
  async getFromJson(optionsJson) {
    ensureWebauthnSupport();
    const options = withPublicKey(JSON.parse(optionsJson));
    const assertion = await webauthnGet(options);
    return JSON.stringify(assertion);
  },
};
