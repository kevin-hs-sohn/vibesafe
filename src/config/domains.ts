/**
 * Trusted domains whitelist for security checks
 *
 * Security note: Some trusted domains have risky subdomains that allow
 * user-generated content. These are checked separately.
 */

/**
 * URL shorteners that can redirect to malicious domains
 * These should always trigger security review
 */
export const URL_SHORTENERS: string[] = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'adf.ly',
  'j.mp',
  'tr.im',
  'short.io',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'tiny.cc',
  'bc.vc',
  'v.gd',
  'x.co',
];

// Domains that are considered safe for script downloads and package installations
export const TRUSTED_DOMAINS: string[] = [
  // Package managers & registries
  'npmjs.com',
  'registry.npmjs.org',
  'yarnpkg.com',
  'pypi.org',
  'pypa.io',
  'crates.io',
  'rubygems.org',
  'packagist.org',

  // GitHub
  'github.com',
  'raw.githubusercontent.com',
  'gist.github.com',
  'objects.githubusercontent.com',

  // Other Git hosts
  'gitlab.com',
  'bitbucket.org',

  // Runtime installers
  'bun.sh',
  'deno.land',
  'nodejs.org',
  'rustup.rs',

  // Docker
  'get.docker.com',
  'download.docker.com',

  // Homebrew
  'brew.sh',
  'formulae.brew.sh',

  // Cloud providers (official endpoints only - NOT user buckets)
  // Note: amazonaws.com removed because S3 buckets can be user-created
  'storage.googleapis.com',
  'azure.microsoft.com',

  // CDNs for packages
  'unpkg.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',

  // Vercel
  'vercel.com',
  'vercel.sh',
];

/**
 * Risky subdomains that allow user-generated content
 * Even if the parent domain is trusted, these subdomains should NOT be auto-trusted
 */
const RISKY_SUBDOMAIN_PATTERNS: RegExp[] = [
  // AWS S3 buckets - anyone can create
  /\.s3\.amazonaws\.com$/i,
  /\.s3-[a-z0-9-]+\.amazonaws\.com$/i,
  /s3\.[a-z0-9-]+\.amazonaws\.com$/i,

  // GitHub Pages - user-controlled
  /\.github\.io$/i,

  // Vercel user deployments
  /\.vercel\.app$/i,

  // Netlify user deployments
  /\.netlify\.app$/i,

  // Cloudflare Pages
  /\.pages\.dev$/i,

  // Render user deployments
  /\.onrender\.com$/i,

  // Railway user deployments
  /\.up\.railway\.app$/i,

  // Heroku user apps
  /\.herokuapp\.com$/i,

  // GitLab Pages
  /\.gitlab\.io$/i,

  // Firebase Hosting
  /\.web\.app$/i,
  /\.firebaseapp\.com$/i,
];

/**
 * Check if a hostname is a risky user-controlled subdomain
 */
export function isRiskySubdomain(hostname: string): boolean {
  const normalizedHost = hostname.toLowerCase();
  return RISKY_SUBDOMAIN_PATTERNS.some((pattern) => pattern.test(normalizedHost));
}

/**
 * Check if a hostname matches a trusted domain
 * Supports exact match and subdomain matching
 * Also checks for risky user-controlled subdomains
 */
export function isDomainTrusted(hostname: string): boolean {
  const normalizedHost = hostname.toLowerCase();

  // First, check if it's a risky user-controlled subdomain
  if (isRiskySubdomain(normalizedHost)) {
    return false;
  }

  return TRUSTED_DOMAINS.some((domain) => {
    const normalizedDomain = domain.toLowerCase();
    return (
      normalizedHost === normalizedDomain ||
      normalizedHost.endsWith('.' + normalizedDomain)
    );
  });
}

/**
 * Extract hostname from URL safely
 */
export function extractHostname(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return null;
  }
}

/**
 * Check if a URL is from a trusted domain
 */
export function isTrustedUrl(url: string): boolean {
  const hostname = extractHostname(url);
  if (!hostname) {
    return false;
  }
  return isDomainTrusted(hostname);
}

/**
 * Extract all URLs from a command string
 */
export function extractUrls(command: string): string[] {
  const urlPattern = /https?:\/\/[^\s"'<>]+/gi;
  const matches = command.match(urlPattern);
  return matches ?? [];
}

/**
 * Check if a hostname is a URL shortener
 */
export function isUrlShortener(hostname: string): boolean {
  const normalizedHost = hostname.toLowerCase();
  return URL_SHORTENERS.some((shortener) => {
    const normalizedShortener = shortener.toLowerCase();
    return (
      normalizedHost === normalizedShortener ||
      normalizedHost.endsWith('.' + normalizedShortener)
    );
  });
}

/**
 * Check if a URL uses a URL shortener
 */
export function isShortenerUrl(url: string): boolean {
  const hostname = extractHostname(url);
  if (!hostname) {
    return false;
  }
  return isUrlShortener(hostname);
}

/**
 * Check if command contains any URL shortener URLs
 */
export function containsUrlShortener(command: string): { found: boolean; shortenerUrls: string[] } {
  const urls = extractUrls(command);
  const shortenerUrls = urls.filter((url) => isShortenerUrl(url));
  return {
    found: shortenerUrls.length > 0,
    shortenerUrls,
  };
}
