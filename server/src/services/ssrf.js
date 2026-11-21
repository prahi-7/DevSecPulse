import dns from 'node:dns/promises';
import ipaddr from 'ipaddr.js';

const allowedPorts = new Set(['80', '443']);

// Check whether an IP address is suitable for a public scan.
export function isPublicIP(value) {
  try {
    if (typeof value !== 'string' || !ipaddr.isValid(value)) {
      return false;
    }

    const parsed = ipaddr.parse(value);

    // Handle IPv4-mapped IPv6 addresses.
    if (
      parsed.kind() === 'ipv6' &&
      parsed.isIPv4MappedAddress()
    ) {
      return isPublicIP(parsed.toIPv4Address().toString());
    }

    return parsed.range() === 'unicast' && !isSpecial(parsed);
  } catch {
    return false;
  }
}

// Additional reserved or non-public address restrictions.
function isSpecial(ip) {
  if (ip.kind() === 'ipv4') {
    const a = ip.octets;

    return (
      a[0] === 0 ||
      a[0] === 10 ||
      a[0] === 127 ||
      a[0] >= 224 ||
      (a[0] === 100 && a[1] >= 64 && a[1] <= 127) ||
      (a[0] === 169 && a[1] === 254) ||
      (a[0] === 172 && a[1] >= 16 && a[1] <= 31) ||
      (a[0] === 192 && (a[1] === 0 || a[1] === 168)) ||
      (a[0] === 198 && (a[1] === 18 || a[1] === 19)) ||
      (a[0] === 203 && a[1] === 0 && a[2] === 113) ||
      (a[0] === 198 && a[1] === 51 && a[2] === 100) ||
      (a[0] === 192 && a[1] === 0 && a[2] === 2) ||
      a[0] === 255
    );
  }

  const s = ip.toNormalizedString();

  return (
    s === '::' ||
    s === '::1' ||
    s.startsWith('64:ff9b:1:') ||
    s.startsWith('2001:db8:') ||
    s.startsWith('2002:') ||
    s.startsWith('fc') ||
    s.startsWith('fd') ||
    s.startsWith('fe8') ||
    s.startsWith('fe9') ||
    s.startsWith('fea') ||
    s.startsWith('feb')
  );
}

// Validate the target URL.
export function parseTarget(raw) {
  if (typeof raw !== 'string' || raw.length > 2048) {
    throw new Error('Invalid URL');
  }

  let u;

  try {
    u = new URL(raw);
  } catch {
    throw new Error('Invalid URL');
  }

  if (
    !['http:', 'https:'].includes(u.protocol) ||
    u.username ||
    u.password ||
    u.hash ||
    !u.hostname
  ) {
    throw new Error(
      'Only public HTTP(S) URLs without credentials or fragments are allowed'
    );
  }

  if (u.port && !allowedPorts.has(u.port)) {
    throw new Error('Only ports 80 and 443 are allowed');
  }

  const hostname = u.hostname.toLowerCase();

  if (
    hostname.endsWith('.') ||
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    throw new Error('Internal hostnames are blocked');
  }

  const ip = hostname.replace(/^\[|\]$/g, '');

  if (ipaddr.isValid(ip) && !isPublicIP(ip)) {
    throw new Error('Non-public IP blocked');
  }

  return u;
}

// Resolve DNS and reject non-public destinations.
export async function resolvePublic(raw, resolver = dns.lookup) {
  const u = parseTarget(raw);

  const results = await resolver(u.hostname, {
    all: true,
    verbatim: true
  });

  if (
    !Array.isArray(results) ||
    !results.length ||
    results.some(
      entry =>
        !entry ||
        !isPublicIP(entry.address)
    )
  ) {
    throw new Error('DNS resolved to a non-public address');
  }

  return {
    url: u,
    addresses: results
  };
}