// Recognizing credentials written in plain text, and masking them before anything is printed. A
// finding never carries a secret: only its kind, its length and its first characters.

interface Pattern {
  kind: string;
  regex: RegExp;
}

// Well-known token formats. Each one is specific enough to flag on its own.
const PATTERNS: readonly Pattern[] = [
  { kind: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/ },
  { kind: "OpenAI API key", regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}/ },
  { kind: "GitHub token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})/ },
  { kind: "GitLab token", regex: /\bglpat-[A-Za-z0-9_-]{20,}/ },
  { kind: "Slack token", regex: /\bxox[abpors]-[A-Za-z0-9-]{10,}/ },
  { kind: "AWS access key", regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/ },
  { kind: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { kind: "Stripe secret key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/ },
  { kind: "Supabase secret key", regex: /\bsb_secret_[A-Za-z0-9_-]{20,}/ },
  { kind: "Resend API key", regex: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/ },
  { kind: "Hugging Face token", regex: /\bhf_[A-Za-z0-9]{30,}/ },
  { kind: "npm token", regex: /\bnpm_[A-Za-z0-9]{36}\b/ },
  { kind: "Notion token", regex: /\b(?:secret|ntn)_[A-Za-z0-9]{40,}/ },
  { kind: "Linear API key", regex: /\blin_api_[A-Za-z0-9]{30,}/ },
  { kind: "PostHog personal API key", regex: /\bphx_[A-Za-z0-9]{30,}/ },
  { kind: "private key", regex: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  { kind: "JSON Web Token", regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { kind: "database URL with password", regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/]{3,}@[^\s/]+/i },
];

// Names that say the value is a credential. A value under such a name is flagged when it looks like
// a literal secret rather than a reference to one (${VAR}, $VAR, an empty or placeholder value).
const SECRET_NAME = /(?:^|[_-])(?:api[_-]?key|apikey|token|secret|password|passwd|pwd|auth|authorization|proxy[_-]?authorization|cookie|credential|private[_-]?key|access[_-]?key|client[_-]?secret|bearer|session)(?:$|[_-])/i;

const REFERENCE = /^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[^}]+\}\}|\$\{input:[^}]+\}|\$\{env:[^}]+\})$/;
const PLACEHOLDER = /^(?:|x+|\*+|<[^>]*>|your[_-].*|changeme|replace[_-]?me|todo|example|xxx.*|none|null|undefined|true|false)$/i;

export interface SecretMatch {
  kind: string;
  masked: string;
}

/** A credential inside a value, by its format. */
export function findSecret(value: string): SecretMatch | null {
  for (const pattern of PATTERNS) {
    const match = pattern.regex.exec(value);
    if (match) return { kind: pattern.kind, masked: mask(match[0]) };
  }
  return null;
}

/** A credential by its name: KEY=value where the name says it is secret and the value is literal. */
export function findNamedSecret(name: string, value: string): SecretMatch | null {
  const direct = findSecret(value);
  if (direct) return direct;
  if (!SECRET_NAME.test(name)) return null;
  const trimmed = value.trim();
  if (REFERENCE.test(trimmed) || PLACEHOLDER.test(trimmed)) return null;
  if (trimmed.length < 8) return null;
  // "Bearer <token>" in a header: the token is the secret.
  const bearer = /^(?:bearer|token|basic)\s+(\S+)$/i.exec(trimmed);
  if (bearer) {
    const token = bearer[1] as string;
    return REFERENCE.test(token) ? null : { kind: `${name} value`, masked: mask(token) };
  }
  return { kind: `${name} value`, masked: mask(trimmed) };
}

/** Shows only the first characters, enough to recognize which key it is, and the length. */
export function mask(secret: string): string {
  const visible = secret.length >= 16 ? 4 : secret.length >= 10 ? 2 : 0;
  return `${secret.slice(0, visible)}${"•".repeat(6)} (${secret.length} chars)`;
}

/** Masks every credential a pattern recognizes inside free text (commands, URLs), as a last guard. */
export function redact(text: string): string {
  let result = text;
  for (const pattern of PATTERNS) {
    const global = new RegExp(pattern.regex.source, pattern.regex.flags.includes("g") ? pattern.regex.flags : `${pattern.regex.flags}g`);
    result = result.replace(global, (match) => mask(match));
  }
  return result;
}
