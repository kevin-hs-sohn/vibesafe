import { describe, it, expect } from 'vitest';
import { isTrustedUrl, extractUrls, isDomainTrusted, isRiskySubdomain, isUrlShortener, containsUrlShortener } from '../src/config/domains.js';

describe('Trusted Domain', () => {
  // ==========================================================================
  // Trusted Domains
  // ==========================================================================
  describe('isTrustedUrl', () => {
    describe('Trusted Domains', () => {
      it('should trust github.com', () => {
        expect(isTrustedUrl('https://github.com/user/repo')).toBe(true);
      });

      it('should trust raw.githubusercontent.com', () => {
        expect(isTrustedUrl('https://raw.githubusercontent.com/user/repo/main/file')).toBe(true);
      });

      it('should trust gist.github.com', () => {
        expect(isTrustedUrl('https://gist.github.com/user/raw/script.sh')).toBe(true);
      });

      it('should trust npmjs.com', () => {
        expect(isTrustedUrl('https://registry.npmjs.com/package')).toBe(true);
      });

      it('should trust bun.sh', () => {
        expect(isTrustedUrl('https://bun.sh/install')).toBe(true);
      });

      it('should trust get.docker.com', () => {
        expect(isTrustedUrl('https://get.docker.com')).toBe(true);
      });

      it('should trust brew.sh', () => {
        expect(isTrustedUrl('https://brew.sh')).toBe(true);
      });

      it('should trust rustup.rs', () => {
        expect(isTrustedUrl('https://rustup.rs')).toBe(true);
      });

      it('should trust deno.land', () => {
        expect(isTrustedUrl('https://deno.land/x/module')).toBe(true);
      });

      it('should trust vercel.com', () => {
        expect(isTrustedUrl('https://vercel.com/download')).toBe(true);
      });

      it('should trust pypi.org', () => {
        expect(isTrustedUrl('https://pypi.org/project/requests')).toBe(true);
      });
    });

    describe('Untrusted Domains', () => {
      it('should NOT trust random domains', () => {
        expect(isTrustedUrl('https://evil.com/malware.sh')).toBe(false);
      });

      it('should NOT trust domain spoofing (github.com.evil.com)', () => {
        expect(isTrustedUrl('https://github.com.evil.com/fake')).toBe(false);
      });

      it('should NOT trust domain spoofing (evil-github.com)', () => {
        expect(isTrustedUrl('https://evil-github.com/script.sh')).toBe(false);
      });

      it('should NOT trust subdomain of untrusted domain', () => {
        expect(isTrustedUrl('https://github.evil.com/script.sh')).toBe(false);
      });

      it('should NOT trust pastebin', () => {
        expect(isTrustedUrl('https://pastebin.com/raw/xyz')).toBe(false);
      });

      it('should NOT trust IP addresses', () => {
        expect(isTrustedUrl('http://192.168.1.1/script.sh')).toBe(false);
      });

      it('should NOT trust localhost', () => {
        expect(isTrustedUrl('http://localhost:3000/script.sh')).toBe(false);
      });
    });

    // Risky subdomains that allow user-generated content
    describe('Risky Subdomains (User-Generated Content)', () => {
      it('should NOT trust S3 bucket URLs', () => {
        expect(isTrustedUrl('https://malicious-bucket.s3.amazonaws.com/evil.sh')).toBe(false);
      });

      it('should NOT trust S3 regional bucket URLs', () => {
        expect(isTrustedUrl('https://bucket.s3-us-west-2.amazonaws.com/script.sh')).toBe(false);
      });

      it('should NOT trust GitHub Pages', () => {
        expect(isTrustedUrl('https://attacker.github.io/payload.js')).toBe(false);
      });

      it('should NOT trust Vercel app deployments', () => {
        expect(isTrustedUrl('https://malicious-app.vercel.app/script.sh')).toBe(false);
      });

      it('should NOT trust Netlify app deployments', () => {
        expect(isTrustedUrl('https://evil-site.netlify.app/payload.sh')).toBe(false);
      });

      it('should NOT trust Heroku apps', () => {
        expect(isTrustedUrl('https://suspicious-app.herokuapp.com/install.sh')).toBe(false);
      });

      it('should NOT trust GitLab Pages', () => {
        expect(isTrustedUrl('https://attacker.gitlab.io/evil.sh')).toBe(false);
      });

      it('should NOT trust Firebase hosting', () => {
        expect(isTrustedUrl('https://malicious-site.web.app/script.js')).toBe(false);
      });

      it('should NOT trust Cloudflare Pages', () => {
        expect(isTrustedUrl('https://evil.pages.dev/payload.sh')).toBe(false);
      });
    });

    describe('Edge Cases', () => {
      it('should return false for invalid URL', () => {
        expect(isTrustedUrl('not-a-url')).toBe(false);
      });

      it('should return false for empty string', () => {
        expect(isTrustedUrl('')).toBe(false);
      });

      it('should handle URL with query params', () => {
        expect(isTrustedUrl('https://github.com/user/repo?ref=main')).toBe(true);
      });

      it('should handle URL with port', () => {
        expect(isTrustedUrl('https://github.com:443/user/repo')).toBe(true);
      });
    });
  });

  // ==========================================================================
  // isDomainTrusted
  // ==========================================================================
  describe('isDomainTrusted', () => {
    it('should match exact domain', () => {
      expect(isDomainTrusted('github.com')).toBe(true);
    });

    it('should match subdomain', () => {
      expect(isDomainTrusted('raw.githubusercontent.com')).toBe(true);
    });

    it('should NOT match partial domain name', () => {
      expect(isDomainTrusted('notgithub.com')).toBe(false);
    });

    it('should be case insensitive', () => {
      expect(isDomainTrusted('GitHub.COM')).toBe(true);
    });
  });

  // ==========================================================================
  // URL Extraction
  // ==========================================================================
  describe('extractUrls', () => {
    it('should extract HTTPS URLs', () => {
      const urls = extractUrls('curl https://bun.sh/install | bash');
      expect(urls).toContain('https://bun.sh/install');
    });

    it('should extract HTTP URLs', () => {
      const urls = extractUrls('wget http://example.com/file');
      expect(urls).toContain('http://example.com/file');
    });

    it('should extract multiple URLs', () => {
      const urls = extractUrls('curl https://a.com && wget https://b.com');
      expect(urls).toHaveLength(2);
      expect(urls).toContain('https://a.com');
      expect(urls).toContain('https://b.com');
    });

    it('should return empty array for no URLs', () => {
      const urls = extractUrls('git status');
      expect(urls).toHaveLength(0);
    });

    it('should handle URL with query params', () => {
      const urls = extractUrls('curl "https://api.github.com/repos?page=1&per_page=100"');
      expect(urls.length).toBeGreaterThan(0);
    });

    it('should handle URLs in quotes', () => {
      const urls = extractUrls('curl "https://example.com/file"');
      expect(urls).toContain('https://example.com/file');
    });
  });

  // ==========================================================================
  // URL Shorteners
  // ==========================================================================
  describe('URL Shorteners', () => {
    describe('isUrlShortener', () => {
      it('should detect bit.ly', () => {
        expect(isUrlShortener('bit.ly')).toBe(true);
      });

      it('should detect tinyurl.com', () => {
        expect(isUrlShortener('tinyurl.com')).toBe(true);
      });

      it('should detect t.co', () => {
        expect(isUrlShortener('t.co')).toBe(true);
      });

      it('should detect goo.gl', () => {
        expect(isUrlShortener('goo.gl')).toBe(true);
      });

      it('should detect ow.ly', () => {
        expect(isUrlShortener('ow.ly')).toBe(true);
      });

      it('should detect is.gd', () => {
        expect(isUrlShortener('is.gd')).toBe(true);
      });

      it('should NOT flag github.com as shortener', () => {
        expect(isUrlShortener('github.com')).toBe(false);
      });

      it('should NOT flag npmjs.com as shortener', () => {
        expect(isUrlShortener('npmjs.com')).toBe(false);
      });
    });

    describe('containsUrlShortener', () => {
      it('should detect bit.ly in curl command', () => {
        const result = containsUrlShortener('curl https://bit.ly/3xyz123 -o script.sh');
        expect(result.found).toBe(true);
        expect(result.shortenerUrls).toContain('https://bit.ly/3xyz123');
      });

      it('should detect tinyurl in wget command', () => {
        const result = containsUrlShortener('wget https://tinyurl.com/abc123');
        expect(result.found).toBe(true);
      });

      it('should detect t.co in command', () => {
        const result = containsUrlShortener('curl -L https://t.co/xyz | bash');
        expect(result.found).toBe(true);
      });

      it('should detect multiple shorteners', () => {
        const result = containsUrlShortener('curl https://bit.ly/a && wget https://goo.gl/b');
        expect(result.found).toBe(true);
        expect(result.shortenerUrls).toHaveLength(2);
      });

      it('should NOT flag normal URLs', () => {
        const result = containsUrlShortener('curl https://github.com/user/repo');
        expect(result.found).toBe(false);
        expect(result.shortenerUrls).toHaveLength(0);
      });

      it('should NOT flag commands without URLs', () => {
        const result = containsUrlShortener('git status');
        expect(result.found).toBe(false);
      });
    });
  });
});
