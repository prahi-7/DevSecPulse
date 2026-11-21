
import http from 'node:http';
import https from 'node:https';
import ipaddr from 'ipaddr.js';
import { resolvePublic, isPublicIP } from './ssrf.js';

const MAX_BYTES = 65536;
const TIMEOUT = 5000;
const MAX_REDIRECTS = 2;

export async function safeRequest(
  input,
  { resolver, depth = 0, signal } = {}
) {
  if (depth > MAX_REDIRECTS) {
    throw new Error('Too many redirects');
  }

  if (signal?.aborted) {
    throw new Error('Scan cancelled');
  }

  const { url, addresses } = await resolvePublic(input, resolver);

  if (signal?.aborted) {
    throw new Error('Scan cancelled');
  }

  const normalizeIP = (address) => {
    if (typeof address !== 'string' || !ipaddr.isValid(address)) {
      throw new Error(`Invalid IP address: ${String(address)}`);
    }

    const parsed = ipaddr.parse(address);

    if (
      parsed.kind() === 'ipv6' &&
      parsed.isIPv4MappedAddress()
    ) {
      return parsed.toIPv4Address().toString();
    }

    return parsed.toNormalizedString();
  };

  const allowedAddresses = new Set(
    addresses.map(entry => normalizeIP(entry.address))
  );

  const validAddresses = addresses
    .filter(entry => isPublicIP(entry.address))
    .sort((a, b) => {
      if (a.family === b.family) return 0;
      return a.family === 4 ? -1 : 1;
    });

  if (!validAddresses.length) {
    throw new Error('No valid public IP address available');
  }

  const lib = url.protocol === 'https:' ? https : http;

  const result = await new Promise((resolve, reject) => {
    let settled = false;
    let verified = false;
    let bytes = 0;
    let deadline;

    const cleanup = () => {
      clearTimeout(deadline);
      signal?.removeEventListener('abort', onAbort);
    };

    const fail = (error) => {
      if (settled) return;

      settled = true;
      cleanup();
      req.destroy();
      reject(error);
    };

    const onAbort = () => {
      fail(new Error('Scan cancelled'));
    };

    const req = lib.request(
      url,
      {
        method: 'GET',

        headers: {
          'user-agent': 'DevSecPulse/1.0 (defensive security audit)',
          accept: '*/*',
          connection: 'close'
        },

        timeout: TIMEOUT,
        maxHeaderSize: 16384,
        rejectUnauthorized: true,
        agent: false,

        lookup: (_hostname, options, callback) => {
          const chosen = validAddresses[0];

          if (options?.all) {
            return callback(
              null,
              [{
                address: chosen.address,
                family: chosen.family
              }]
            );
          }

          callback(null, chosen.address, chosen.family);
        }
      },

      
(res) => {
  if (settled) return;

  if (!verified) {
    fail(new Error('Connection destination not verified'));
    return;
  }

  const result = {
    status: res.statusCode,
    headers: res.headers,
    certificate: req.socket?.getPeerCertificate?.(),
    authorized: req.socket?.authorized,
    authorizationError: req.socket?.authorizationError,
    url: url.href
  };

  settled = true;
  cleanup();

  // The audit only needs headers and TLS information.
  // Stop receiving the response body.
  res.destroy();

  resolve(result);
});

    req.on('socket', socket => {
      const verifyConnection = () => {
        if (settled) return;

        try {
          const remoteAddress = socket.remoteAddress;

          console.log('CONNECTED IP:', remoteAddress);

          if (!remoteAddress) {
            throw new Error('Connected IP address unavailable');
          }

          const connectedIP = normalizeIP(remoteAddress);

          if (
            !isPublicIP(remoteAddress) ||
            !allowedAddresses.has(connectedIP)
          ) {
            throw new Error('Connection destination not allowed');
          }

          verified = true;
        } catch (error) {
          fail(error);
        }
      };

      // Verify the TCP connection before TLS completes.
      socket.once('connect', verifyConnection);
    });

    req.on('timeout', () => {
      fail(new Error('Connection timeout'));
    });

    req.on('error', error => {
      fail(error);
    });

    deadline = setTimeout(() => {
      fail(new Error('Request deadline exceeded'));
    }, TIMEOUT);

    signal?.addEventListener('abort', onAbort, { once: true });

    if (signal?.aborted) {
      onAbort();
    } else {
      req.end();
    }
  });

  if (
    [301, 302, 303, 307, 308].includes(result.status) &&
    result.headers.location
  ) {
    const next = new URL(
      result.headers.location,
      url
    ).href;

    const redirected = await safeRequest(next, {
      resolver,
      depth: depth + 1,
      signal
    });

    return {
      ...redirected,
      redirects: (redirected.redirects ?? 0) + 1,
      redirectedFrom: input
    };
  }

  return {
    ...result,
    redirects: 0
  };
}
