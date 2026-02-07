---
name: security-patterns
description: vibesafu security pattern definitions and update guidelines.
---

# Instant Block Patterns

## Reverse Shell

```typescript
const REVERSE_SHELL_PATTERNS = [
  /bash\s+-i\s+>&\s+\/dev\/tcp/i,
  /nc\s+-e\s+\/bin\/(ba)?sh/i,
  /python[23]?\s+-c\s+['"]import\s+socket/i,
  /perl\s+-e\s+['"]use\s+Socket/i,
];
```

## Data Exfiltration

```typescript
const DATA_EXFIL_PATTERNS = [
  /curl.*\$\{?[A-Z_]*KEY/i,           // curl with API key
  /curl.*\$\{?[A-Z_]*TOKEN/i,         // curl with token
  /wget.*\$\{?[A-Z_]*SECRET/i,        // wget with secret
  /curl\s+.*--data.*\$\{?[A-Z_]/i,    // POST with env var
];
```

## Crypto Mining

```typescript
const CRYPTO_MINING_PATTERNS = [
  /xmrig/i,
  /minerd/i,
  /cpuminer/i,
  /stratum\+tcp/i,
];
```

## Pattern Update Rules

1. Write test cases before adding new patterns
2. Validate false positives (ensure normal commands aren't blocked)
3. Performance testing (regex complexity)
4. Documentation (why this pattern is needed)

# Trusted Domains

```typescript
const TRUSTED_DOMAINS = [
  'github.com',
  'raw.githubusercontent.com',
  'bun.sh',
  'deno.land',
  'nodejs.org',
  'npmjs.com',
  'registry.npmjs.org',
  'get.docker.com',
  'brew.sh',
  'rustup.rs',
  'pypa.io',
  'pypi.org',
];
```
