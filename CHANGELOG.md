# 변경 사항 (CHANGELOG)

## [Unreleased]

### 추가
- `appguardrail fix` 명령 — 안전하고 결정적인 자동 수정을 적용합니다(기본 dry-run diff, `--apply`로 기록). 의미를 바꾸지 않는 순수 additive 변환만 수행하며, 첫 변환으로 외부 `target="_blank"` 링크에 `rel="noopener noreferrer"`를 추가합니다(reverse tabnabbing 방지). 동작을 바꾸는 수정(시크릿→env 등)은 위험하므로 자동 적용하지 않고 fix-pack 프롬프트로 남깁니다. scan→fix→verify 루프를 안전하게 닫습니다.
- `appguardrail serve` — 멀티테넌트 **control-plane API**(스캔 인제스트 + 히스토리). 일회성 CLI를 넘어, CI가 매 스캔의 `appguardrail.findings.v1`을 org별 API 키로 영속 저장하고 시간에 따른 추이를 조회할 수 있는 지속형 백본입니다. stdlib(sqlite3 + http.server)만 사용하며 org별 테넌트 격리를 강제합니다.
  - 엔드포인트: `POST /api/v1/scans`(인제스트), `GET /api/v1/scans`(히스토리), `GET /api/v1/scans/{id}`(상세), `GET /api/v1/health`.
  - 인증: `Authorization: Bearer <api_key>`. `--create-org <name>`으로 org·키 발급, 빈 DB면 기본 org를 부트스트랩합니다.

### 추가
- 프로젝트 설정 파일 `.appguardrail.json`(선택) — deploy 게이트를 CLI 플래그 없이 팀 단위로 조정합니다. 무의존성 유지를 위해 JSON을 사용합니다.
  - `fail_on`: 게이트를 실패시키는 최소 severity(예: `"HIGH"`, `"CRITICAL"`). 기본은 CRITICAL·HIGH.
  - `exclude_rules`: 게이트에서 제외할 rule id 목록(억제). 잘못된 값은 스캔을 조용히 통과시키지 않고 오류로 실패합니다.
- 탐지 룰 추가(AI-built 앱 스택 정밀 룰, 저 오탐):
  - `sql-injection-raw-unsafe` — Prisma `$queryRawUnsafe`/`$executeRawUnsafe`(파라미터화 없이 SQL 주입 가능). CRITICAL.
  - `react-dangerously-set-inner-html` — React `dangerouslySetInnerHTML`(사용자 입력 시 XSS). HIGH.
  - `hardcoded-anthropic-api-key` — `sk-ant-…` Claude API 키 하드코딩. CRITICAL.
- 시크릿·주입 탐지 룰 8종 추가(고정밀, 안전 코드 오탐 0 검증):
  - `hardcoded-aws-access-key-id`(AKIA/ASIA), `hardcoded-github-token`(ghp_/github_pat_), `hardcoded-google-api-key`(AIza), `hardcoded-private-key-block`(PEM) — 모두 CRITICAL.
  - `supabase-auth-admin-client-usage`(auth.admin.* 클라이언트 노출), `node-open-redirect-user-input`(req 입력 redirect), `insecure-random-security-token`(토큰에 Math.random) — HIGH.
  - `wildcard-postmessage-target`(postMessage 대상 '*') — WARNING.

### 추가
- `appguardrail scan --sarif <path>` — 정규화된 findings를 SARIF 2.1.0으로 출력합니다. GitHub code scanning(`github/codeql-action/upload-sarif`), VS Code SARIF viewer, Azure DevOps 등 SARIF 소비 도구가 그대로 읽어 Security tab 알림·PR 인라인 주석으로 표시됩니다. severity→level 매핑과 GitHub 랭킹용 `security-severity` 속성, deploy-gate 의미(`deployBlocking`), 재실행 간 안정적인 `partialFingerprints`를 포함합니다.
- `appguardrail monitor`가 설치하는 워크플로가 이제 SARIF를 생성해 GitHub code scanning에 업로드합니다(`security-events: write`). deploy 게이트는 그대로 유지됩니다.
- `appguardrail dashboard` 명령을 추가했습니다. `scan --findings-json`이 생성한 `appguardrail.findings.v1` 파일을 로컬 웹 대시보드로 렌더링합니다. severity 요약, deploy-blocking 게이트, 카테고리별 findings, 그리고 finding별 상세(AppGuardrail Fix Format: Problem / Fix Prompt / Verification)를 보여줍니다.
  - 옵션: `--findings`, `--port`, `--host`, `--no-open`.
  - 대시보드는 프레임워크·빌드 단계가 없는 단일 정적 페이지(`scanner/dashboard/index.html`)이며, wheel에 포함되어 `pip install` 설치본에서도 동작합니다.
  - findings 파일을 `/findings.json`으로 직접 서빙하여 실행 위치(cwd)와 무관하게 로드됩니다.

### 검증
- `tests/test_dashboard_core.py`: 정적 자산 동봉 여부, HTTP 라우트(`/`, `/findings.json`, 404) 테스트를 추가했습니다.
- 격리된 venv에 wheel을 설치해 소스 트리 밖에서 `appguardrail dashboard`가 대시보드를 서빙함을 확인했습니다.

## [0.1.1] - 2026-06-25

### 변경
- PyPI Trusted Publishing 경로 검증을 위한 패치 릴리스로 CLI 버전을 `0.1.1`로 갱신했습니다.

### 검증
- GitHub `pypi` environment와 PyPI Trusted Publisher 설정을 사용해 GitHub Actions OIDC 게시 경로를 검증합니다.

## [0.1.0] - 2026-06-25

### 변경
- 프로젝트명을 AppGuardrail로 변경했습니다. 기존 VibeSec 이름은 제3자 PyPI `vibesec` 네임스페이스와 충돌할 수 있어, 설치 경로와 공개 식별자의 신뢰성을 높이기 위한 조치입니다.
- 문서화된 CLI 명령, 생성 rule 파일명, scan artifact 이름, 저장소 참조를 `appguardrail` 기준으로 갱신했습니다.

### 추가
- PyPI 배포를 위한 `pyproject.toml`, package discovery 설정, `appguardrail` console script entry point를 추가했습니다.
- GitHub Actions 기반 PyPI Trusted Publishing workflow를 추가했습니다.
- `scanner/cli/appguardrail.py`의 100% 테스트 커버리지를 달성하기 위해 `tests/test_appguardrail_coverage.py` 테스트 파일을 추가했습니다.
  - `cmd_init`: `claude-code` 사용 시 `append_marker` 관련 파일 생성 및 심볼릭 링크 예외, 경로 이탈(`path traversal`) 방지 테스트 추가.
  - `cmd_scan`: 존재하지 않는 경로 및 심볼릭 링크 경로 스캔 시 예외 처리 테스트 추가.
  - `cmd_hook`: `.git` 디렉토리 부재 시 에러 반환, 훅 스크립트의 정상 설치, 심볼릭 링크 처리 및 경로 이탈 방지 테스트 추가.
  - 파일 시스템 IO: 파일 디렉토리 순회(`_collect_files`) 시 `os.scandir` 및 하위 노드의 `OSError` 처리 테스트 추가. 파일 정보 획득(`os.lstat`) 과정의 권한 및 예외(`OSError`) 처리 테스트 추가.
  - `cmd_review`: `--stack`, `--db`, `--payments` 인자 유무에 따른 프롬프트 생성 분기 테스트 추가.
  - `main` 함수: 터미널 인자(args) 파싱 및 서브 커맨드(`init`, `scan`, `review`, `hook`) 호출, 그리고 인자가 없을 때의 예외 동작을 포함한 테스트 추가.
  - `if __name__ == '__main__':` 블록의 실행 테스트 추가.
- `scanner/cli/appguardrail.py`의 엣지 케이스를 커버하기 위한 `tests/test_coverage_edge_cases.py` 테스트 파일을 추가했습니다.
  - `_run_trivy_fs`: Trivy 스캔 시의 비정상 종료 및 JSON 파싱 에러 처리 테스트 추가.
  - `_finding_context`, `_finding_category`, `_trivy_severity`, `_confidence`, `_is_deploy_blocking` 등 헬퍼 함수들의 다양한 입력값에 대한 반환값 테스트 추가.
  - `_trivy_target`: 절대 경로, 상대 경로 및 빈 문자열 입력 처리 엣지 케이스 추가.

### Performance (성능 개선)
- `scanner/cli/appguardrail.py`에서 `Path.open()` 대신 내장 `open()` 함수를 사용하여 파일 스캔 시 오버헤드 감소
- `_trivy_severity` 및 `_print_scan_results` 함수 내 딕셔너리 객체를 모듈 레벨 상수로 추출하여 메모리 할당 최적화

### 검증
- `scanner/cli/appguardrail.py` 전체 코드에 대한 테스트 커버리지 100% 달성 및 기존 기능의 안정성 확보 검증.
