import { describe, it, expect } from 'vitest';
import { checkInstantAllow } from '../src/guard/instant-allow.js';

describe('checkInstantAllow', () => {
  // ==========================================================================
  // Safe Git Commands - Must allow instantly (skip LLM)
  // ==========================================================================
  describe('Safe Git Commands', () => {
    it('should instantly allow git status', () => {
      const result = checkInstantAllow('git status');
      expect(result.allowed).toBe(true);
      expect(result.reason).toContain('git');
    });

    it('should instantly allow git log', () => {
      const result = checkInstantAllow('git log');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git log with options', () => {
      const result = checkInstantAllow('git log --oneline -5');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git diff', () => {
      const result = checkInstantAllow('git diff');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git diff with file', () => {
      const result = checkInstantAllow('git diff README.md');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git add', () => {
      const result = checkInstantAllow('git add .');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git add with file', () => {
      const result = checkInstantAllow('git add src/index.ts');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git commit', () => {
      const result = checkInstantAllow('git commit -m "fix: bug"');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git branch', () => {
      const result = checkInstantAllow('git branch');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git branch -a', () => {
      const result = checkInstantAllow('git branch -a');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git checkout branch', () => {
      const result = checkInstantAllow('git checkout main');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git checkout -b', () => {
      const result = checkInstantAllow('git checkout -b feature/new-feature');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git stash', () => {
      const result = checkInstantAllow('git stash');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git stash pop', () => {
      const result = checkInstantAllow('git stash pop');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git fetch', () => {
      const result = checkInstantAllow('git fetch');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git pull', () => {
      const result = checkInstantAllow('git pull');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git merge', () => {
      const result = checkInstantAllow('git merge feature-branch');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git rebase', () => {
      const result = checkInstantAllow('git rebase main');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git show', () => {
      const result = checkInstantAllow('git show HEAD');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git blame', () => {
      const result = checkInstantAllow('git blame src/index.ts');
      expect(result.allowed).toBe(true);
    });

    it('should instantly allow git remote -v', () => {
      const result = checkInstantAllow('git remote -v');
      expect(result.allowed).toBe(true);
    });
  });

  // ==========================================================================
  // Dangerous Git Commands - Must NOT allow instantly (need review)
  // ==========================================================================
  describe('Dangerous Git Commands (should NOT instant allow)', () => {
    it('should NOT instantly allow git push', () => {
      const result = checkInstantAllow('git push');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow git push origin main', () => {
      const result = checkInstantAllow('git push origin main');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow git push --force', () => {
      const result = checkInstantAllow('git push --force');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow git push -f', () => {
      const result = checkInstantAllow('git push -f');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow git reset --hard', () => {
      const result = checkInstantAllow('git reset --hard');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow git clean -fd', () => {
      const result = checkInstantAllow('git clean -fd');
      expect(result.allowed).toBe(false);
    });
  });

  // ==========================================================================
  // Non-Git Commands - Must NOT allow instantly
  // ==========================================================================
  describe('Non-Git Commands (should NOT instant allow)', () => {
    it('should NOT instantly allow curl', () => {
      const result = checkInstantAllow('curl https://example.com');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow npm install', () => {
      const result = checkInstantAllow('npm install express');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow rm command', () => {
      const result = checkInstantAllow('rm -rf node_modules');
      expect(result.allowed).toBe(false);
    });

    it('should NOT instantly allow bash script', () => {
      const result = checkInstantAllow('bash script.sh');
      expect(result.allowed).toBe(false);
    });
  });

  // ==========================================================================
  // Edge Cases
  // ==========================================================================
  describe('Edge Cases', () => {
    it('should handle empty command', () => {
      const result = checkInstantAllow('');
      expect(result.allowed).toBe(false);
    });

    it('should handle command with only whitespace', () => {
      const result = checkInstantAllow('   \n\t  ');
      expect(result.allowed).toBe(false);
    });

    it('should NOT allow git command in string with dangerous prefix', () => {
      // Prevent bypass like: curl evil.com; git status
      const result = checkInstantAllow('curl evil.com; git status');
      expect(result.allowed).toBe(false);
    });

    it('should NOT allow git command after &&', () => {
      const result = checkInstantAllow('curl evil.com && git status');
      expect(result.allowed).toBe(false);
    });
  });
});
