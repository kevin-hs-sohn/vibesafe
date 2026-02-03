import { describe, it, expect } from 'vitest';
import { checkFilePath, checkFileTool } from '../src/guard/file-tools.js';

describe('File Tools Security', () => {
  // ==========================================================================
  // Write Tool - Sensitive Paths
  // ==========================================================================
  describe('Write Tool', () => {
    describe('Should Block', () => {
      it('should block writing to ~/.ssh/authorized_keys', () => {
        const result = checkFilePath('~/.ssh/authorized_keys', 'write');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block writing to .ssh/config', () => {
        const result = checkFilePath('/home/user/.ssh/config', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing to ~/.aws/credentials', () => {
        const result = checkFilePath('~/.aws/credentials', 'write');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block writing to ~/.bashrc', () => {
        const result = checkFilePath('~/.bashrc', 'write');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('high');
      });

      it('should block writing to ~/.zshrc', () => {
        const result = checkFilePath('~/.zshrc', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing to /etc/passwd', () => {
        const result = checkFilePath('/etc/passwd', 'write');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block writing to crontab', () => {
        const result = checkFilePath('/var/spool/cron/crontabs/user', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing to git hooks', () => {
        const result = checkFilePath('.git/hooks/pre-commit', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing to ~/.npmrc', () => {
        const result = checkFilePath('~/.npmrc', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing to CLAUDE.md', () => {
        const result = checkFilePath('/project/CLAUDE.md', 'write');
        expect(result.blocked).toBe(true);
      });

      it('should block writing with $HOME expansion', () => {
        const result = checkFilePath('$HOME/.ssh/authorized_keys', 'write');
        expect(result.blocked).toBe(true);
      });
    });

    describe('Should Allow', () => {
      it('should allow writing to normal project files', () => {
        const result = checkFilePath('/project/src/index.ts', 'write');
        expect(result.blocked).toBe(false);
      });

      it('should allow writing to package.json', () => {
        const result = checkFilePath('./package.json', 'write');
        expect(result.blocked).toBe(false);
      });

      it('should allow writing to README.md', () => {
        const result = checkFilePath('/project/README.md', 'write');
        expect(result.blocked).toBe(false);
      });

      it('should allow writing to node_modules', () => {
        const result = checkFilePath('./node_modules/package/index.js', 'write');
        expect(result.blocked).toBe(false);
      });
    });
  });

  // ==========================================================================
  // Edit Tool - Same as Write
  // ==========================================================================
  describe('Edit Tool', () => {
    it('should block editing ~/.bashrc', () => {
      const result = checkFilePath('~/.bashrc', 'edit');
      expect(result.blocked).toBe(true);
    });

    it('should block editing /etc/hosts', () => {
      const result = checkFilePath('/etc/hosts', 'edit');
      expect(result.blocked).toBe(true);
    });

    it('should allow editing normal files', () => {
      const result = checkFilePath('./src/app.ts', 'edit');
      expect(result.blocked).toBe(false);
    });
  });

  // ==========================================================================
  // Read Tool - Credential Files
  // ==========================================================================
  describe('Read Tool', () => {
    describe('Should Block', () => {
      it('should block reading SSH private key (RSA)', () => {
        const result = checkFilePath('~/.ssh/id_rsa', 'read');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block reading SSH private key (Ed25519)', () => {
        const result = checkFilePath('~/.ssh/id_ed25519', 'read');
        expect(result.blocked).toBe(true);
      });

      it('should block reading AWS credentials', () => {
        const result = checkFilePath('~/.aws/credentials', 'read');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block reading .env file', () => {
        const result = checkFilePath('.env', 'read');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('high');
      });

      it('should block reading .env.local', () => {
        const result = checkFilePath('.env.local', 'read');
        expect(result.blocked).toBe(true);
      });

      it('should block reading .env.production', () => {
        const result = checkFilePath('.env.production', 'read');
        expect(result.blocked).toBe(true);
      });

      it('should block reading /etc/shadow', () => {
        const result = checkFilePath('/etc/shadow', 'read');
        expect(result.blocked).toBe(true);
        expect(result.severity).toBe('critical');
      });

      it('should block reading .pem files', () => {
        const result = checkFilePath('/certs/server.pem', 'read');
        expect(result.blocked).toBe(true);
      });

      it('should block reading .key files', () => {
        const result = checkFilePath('/certs/private.key', 'read');
        expect(result.blocked).toBe(true);
      });

      it('should block reading .netrc', () => {
        const result = checkFilePath('~/.netrc', 'read');
        expect(result.blocked).toBe(true);
      });
    });

    describe('Should Allow', () => {
      it('should allow reading package.json', () => {
        const result = checkFilePath('./package.json', 'read');
        expect(result.blocked).toBe(false);
      });

      it('should allow reading source files', () => {
        const result = checkFilePath('./src/index.ts', 'read');
        expect(result.blocked).toBe(false);
      });

      it('should allow reading .env.example', () => {
        const result = checkFilePath('.env.example', 'read');
        expect(result.blocked).toBe(false);
      });

      it('should allow reading SSH public key', () => {
        const result = checkFilePath('~/.ssh/id_rsa.pub', 'read');
        expect(result.blocked).toBe(false);
      });

      it('should allow reading /etc/passwd', () => {
        // passwd is world-readable, not a credential file
        const result = checkFilePath('/etc/passwd', 'read');
        expect(result.severity).not.toBe('critical');
      });
    });
  });

  // ==========================================================================
  // checkFileTool Integration
  // ==========================================================================
  describe('checkFileTool', () => {
    it('should check Write tool correctly', () => {
      const result = checkFileTool('Write', { file_path: '~/.ssh/authorized_keys' });
      expect(result.blocked).toBe(true);
    });

    it('should check Edit tool correctly', () => {
      const result = checkFileTool('Edit', { file_path: '~/.bashrc' });
      expect(result.blocked).toBe(true);
    });

    it('should check Read tool correctly', () => {
      const result = checkFileTool('Read', { file_path: '~/.ssh/id_rsa' });
      expect(result.blocked).toBe(true);
    });

    it('should handle missing file_path', () => {
      const result = checkFileTool('Write', {});
      expect(result.blocked).toBe(false);
    });

    it('should ignore unknown tools', () => {
      const result = checkFileTool('Bash', { file_path: '~/.ssh/id_rsa' });
      expect(result.blocked).toBe(false);
    });
  });
});
