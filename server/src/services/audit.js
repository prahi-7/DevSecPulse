
import { safeRequest } from './httpAudit.js';
import { scoreFindings } from '../utils/scoring.js';

const headerRules = [
  [
    'content-security-policy',
    'CSP',
    'Medium',
    'Add a restrictive Content-Security-Policy header.'
  ],
  [
    'strict-transport-security',
    'HSTS',
    'Medium',
    'Set Strict-Transport-Security with a suitable max-age on HTTPS.'
  ],
  [
    'x-frame-options',
    'X-Frame-Options',
    'Low',
    'Set X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors.'
  ],
  [
    'x-content-type-options',
    'X-Content-Type-Options',
    'Low',
    'Set X-Content-Type-Options: nosniff.'
  ],
  [
    'referrer-policy',
    'Referrer-Policy',
    'Low',
    'Set a restrictive Referrer-Policy.'
  ],
  [
    'permissions-policy',
    'Permissions-Policy',
    'Low',
    'Restrict unnecessary browser capabilities.'
  ]
];

function finding(
  id,
  title,
  severity,
  description,
  evidence,
  remediation
) {
  return {
    id,
    title,
    severity,
    description,
    evidence,
    remediation
  };
}

function headerValue(headers, key) {
  const value = headers[key];

  if (Array.isArray(value)) {
    return value.join(', ');
  }

  return typeof value === 'string' ? value.trim() : '';
}

function validHSTS(value) {
  const match = value.match(
    /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i
  );

  if (!match) return false;

  const maxAge = Number(match[1]);

  return Number.isSafeInteger(maxAge) && maxAge > 0;
}

function validCSP(value) {
  if (!value) return false;

  const directives = value
    .split(';')
    .map(part => part.trim())
    .filter(Boolean);

  const knownDirectives = new Set([
    'default-src',
    'script-src',
    'style-src',
    'img-src',
    'connect-src',
    'font-src',
    'object-src',
    'base-uri',
    'frame-ancestors',
    'form-action',
    'worker-src',
    'child-src',
    'frame-src',
    'media-src',
    'manifest-src'
  ]);

  return directives.some(directive => {
    const [name, ...values] = directive.split(/\s+/);
    return knownDirectives.has(name.toLowerCase()) &&
      values.length > 0;
  });
}

function validFrameAncestors(csp) {
  const directive = csp
    .split(';')
    .map(part => part.trim())
    .find(part => /^frame-ancestors(?:\s|$)/i.test(part));

  if (!directive) return false;

  const values = directive.split(/\s+/).slice(1);

  return values.length > 0 &&
    values.some(value => value.trim().length > 0);
}

function validReferrerPolicy(value) {
  const validPolicies = new Set([
    'no-referrer',
    'no-referrer-when-downgrade',
    'origin',
    'origin-when-cross-origin',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
    'unsafe-url'
  ]);

  const values = value
    .split(',')
    .map(part => part.trim().toLowerCase())
    .filter(Boolean);

  return values.length > 0 &&
    values.some(policy => validPolicies.has(policy));
}

function checkHeader(key, value, headers, url) {
  if (
    key === 'strict-transport-security' &&
    !url.startsWith('https:')
  ) {
    return {
      status: 'inconclusive',
      detail: 'HSTS applies to HTTPS responses'
    };
  }

  if (
    key === 'x-frame-options' &&
    !value &&
    validFrameAncestors(
      headerValue(headers, 'content-security-policy')
    )
  ) {
    return {
      status: 'pass',
      detail: 'Protected by CSP frame-ancestors'
    };
  }

  if (!value) {
    return {
      status: 'finding',
      detail: 'Missing header'
    };
  }

  switch (key) {
    case 'content-security-policy':
      return validCSP(value)
        ? { status: 'pass', detail: value.slice(0, 250) }
        : {
            status: 'finding',
            detail: 'CSP does not contain a recognized directive with values'
          };

    case 'strict-transport-security':
      return validHSTS(value)
        ? { status: 'pass', detail: value.slice(0, 250) }
        : {
            status: 'finding',
            detail: 'Invalid or disabled HSTS max-age'
          };

    case 'x-frame-options': {
      const valid = ['DENY', 'SAMEORIGIN'].includes(
        value.toUpperCase()
      );

      return valid
        ? { status: 'pass', detail: value }
        : {
            status: 'finding',
            detail: `Invalid X-Frame-Options value: ${value}`
          };
    }

    case 'x-content-type-options':
      return value.toLowerCase() === 'nosniff'
        ? { status: 'pass', detail: value }
        : {
            status: 'finding',
            detail: 'Expected nosniff'
          };

    case 'referrer-policy':
      return validReferrerPolicy(value)
        ? { status: 'pass', detail: value.slice(0, 250) }
        : {
            status: 'finding',
            detail: 'Unrecognized Referrer-Policy value'
          };

    default:
      return {
        status: 'pass',
        detail: value.slice(0, 250)
      };
  }
}

export function evaluateResponse(r) {
  const findings = [];
  const checks = [];

  const h = r.headers || {};
  const finalUrl = r.url || '';
  const isHTTPS = finalUrl.startsWith('https:');

  for (const [
    key,
    label,
    severity,
    remediation
  ] of headerRules) {
    const value = headerValue(h, key);

    const result = checkHeader(
      key,
      value,
      h,
      finalUrl
    );

    checks.push({
      name: label,
      status: result.status,
      detail: result.detail
    });

    if (result.status === 'finding') {
      const missing = !value;

      findings.push(
        finding(
          `header-${key}`,
          missing
            ? `Missing ${label}`
            : `Invalid ${label}`,
          severity,
          missing
            ? `${label} was not returned by the audited endpoint.`
            : `${label} was returned but failed configuration validation.`,
          missing
            ? `Header ${key}: absent`
            : `Header ${key}: ${value.slice(0, 250)}`,
          remediation
        )
      );
    }
  }

  // CORS checks
  const origin = headerValue(
    h,
    'access-control-allow-origin'
  );

  const credentials = headerValue(
    h,
    'access-control-allow-credentials'
  );

  if (
    origin === '*' &&
    credentials.toLowerCase() === 'true'
  ) {
    findings.push(
      finding(
        'cors-wildcard-creds',
        'Potentially unsafe CORS combination',
        'High',
        'Wildcard origin is returned alongside credentials. Browsers reject this combination, but it indicates a misconfiguration.',
        `Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: ${credentials}`,
        'Use an explicit allowlist of trusted origins for credentialed requests.'
      )
    );
  } else if (origin === '*') {
    findings.push(
      finding(
        'cors-wildcard',
        'Wildcard CORS origin',
        'Low',
        'Any origin may read non-credentialed responses when browser CORS rules permit.',
        `Access-Control-Allow-Origin: ${origin}`,
        'Restrict cross-origin access when appropriate for the endpoint.'
      )
    );
  }

  checks.push({
    name: 'CORS response headers',
    status: 'checked',
    detail: origin
      ? `ACAO: ${origin}`
      : 'No ACAO header; origin-specific behavior not tested'
  });

  // HTTPS checks
  if (!isHTTPS) {
    findings.push(
      finding(
        'no-https',
        'Endpoint uses HTTP',
        'High',
        'The final response was served without TLS.',
        `Final URL: ${finalUrl}`,
        'Enable HTTPS and redirect HTTP traffic to HTTPS.'
      )
    );
  }

  checks.push({
    name: 'TLS',
    status: isHTTPS ? 'pass' : 'finding',
    detail: isHTTPS
      ? 'TLS handshake and certificate trust verification passed'
      : 'Unencrypted HTTP'
  });

  // Certificate expiry
  if (r.certificate?.valid_to) {
    const expiryDate = new Date(
      r.certificate.valid_to
    );

    const daysRemaining = Math.floor(
      (expiryDate.getTime() - Date.now()) /
      86400000
    );

    if (!Number.isFinite(daysRemaining)) {
      checks.push({
        name: 'Certificate expiry',
        status: 'inconclusive',
        detail: 'Certificate expiry date could not be parsed'
      });
    } else {
      checks.push({
        name: 'Certificate expiry',
        status: daysRemaining < 0
          ? 'finding'
          : 'pass',
        detail: `Expires ${r.certificate.valid_to}`
      });

      if (daysRemaining < 0) {
        findings.push(
          finding(
            'cert-expired',
            'TLS certificate expired',
            'High',
            'The certificate expiry date has passed.',
            `Expiry: ${r.certificate.valid_to}`,
            'Renew the TLS certificate.'
          )
        );
      } else if (daysRemaining < 30) {
        findings.push(
          finding(
            'cert-expiring',
            'TLS certificate expires soon',
            'Medium',
            'The certificate expires within 30 days.',
            `Days remaining: ${daysRemaining}`,
            'Renew the certificate before expiry.'
          )
        );
      }
    }
  } else {
    checks.push({
      name: 'Certificate expiry',
      status: 'inconclusive',
      detail: 'No certificate information available'
    });
  }

  // Redirect information
  checks.push({
    name: 'HTTPS redirects',
    status: 'checked',
    detail: `${r.redirects ?? 0} redirect(s); final URL ${finalUrl}`
  });

  const { score, grade } = scoreFindings(findings);

  return {
    status: checks.some(
      check => check.status === 'inconclusive'
    )
      ? 'partial'
      : 'completed',
    findings,
    checks,
    score,
    grade,
    finalUrl,
    httpStatus: r.status,
    redirectCount: r.redirects ?? 0
  };
}

export async function auditURL(
  url,
  request = safeRequest
) {
  try {
    const response = await request(url);

    return evaluateResponse(response);
  } catch (error) {
    const message = String(
      error.message || 'Request failed'
    ).slice(0, 300);

    console.error('AUDIT ERROR:', message);

    return {
      status: 'failed',
      findings: [],
      checks: [
        {
          name: 'Connection',
          status: 'failed',
          detail: message
        }
      ],
      error: message,
      score: null,
      grade: null
    };
  }
}
