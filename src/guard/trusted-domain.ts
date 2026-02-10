/**
 * Trusted Domain - Check if URLs are from trusted sources
 */

import { isTrustedUrl, extractUrls } from '../config/domains.js';

export interface TrustedDomainResult {
  allTrusted: boolean;
  urls: string[];
  trustedUrls: string[];
  untrustedUrls: string[];
}

/**
 * Check all URLs in a command and determine if they're from trusted domains
 */
export function checkTrustedDomains(command: string): TrustedDomainResult {
  const urls = extractUrls(command);

  if (urls.length === 0) {
    return {
      allTrusted: true, // No URLs means nothing untrusted
      urls: [],
      trustedUrls: [],
      untrustedUrls: [],
    };
  }

  const trustedUrls: string[] = [];
  const untrustedUrls: string[] = [];

  for (const url of urls) {
    if (isTrustedUrl(url)) {
      trustedUrls.push(url);
    } else {
      untrustedUrls.push(url);
    }
  }

  return {
    allTrusted: untrustedUrls.length === 0,
    urls,
    trustedUrls,
    untrustedUrls,
  };
}

