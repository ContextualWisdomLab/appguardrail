# 변경 사항 (CHANGELOG)

## [Unreleased]

### 보안
- 리포트 출력 하드닝 — 생성된 markdown 리포트가 HTML로 렌더될 때 악성 finding 내용(예: 외부 엔진이 스캔한 코드의 `<script>`)이 주입되지 않도록, 프로즈 필드(message/remediation/verification)를 HTML 이스케이프하고 snippet의 code-fence 탈출을 무력화합니다(모든 리포트 타입). rule_id/category/context 등 제약된 식별자는 그대로 둡니다.
- control plane API 하드닝: (1) 요청 본문을 10MiB로 캡하고 음수 Content-Length를 거부합니다(유효 키 소지자의 OOM/EOF-hang 방지). (2) `limit`/`offset` 쿼리 파라미터를 클램프합니다 — sqlite에서 `LIMIT -1`은 무제한이므로 음수를 그대로 전달하면 페이지네이션 캡이 우회됐습니다(list 1..1000, trend 1..365, offset ≥0).

### 추가
- **공식 Docker 이미지 정의**(`Dockerfile` + `.dockerignore`) — 설치 없이 스캔합니다: `docker build -t appguardrail . && docker run --rm -v "$PWD:/src" appguardrail scan /src`. `python:3.12-slim` 이미지를 digest로 고정하고, 로컬 소스를 `PYTHONPATH=/app`에서 모듈로 실행해 컨테이너 빌드 중 `pip install` 공급망 단계를 제거합니다. 비루트(`scanner`) 사용자와 `HEALTHCHECK`를 포함하며, exit code 계약은 CLI와 동일합니다(1 = deploy-blocking).
- PHP / WordPress 룰팩 `scanner/rules/php-wordpress.yml` 추가 — 바이브 코딩·에이전시 산출물에 많은 PHP/WordPress 코드를 처음으로 커버합니다. 기존 내장 eval/SQL 룰은 `.js`/`.py` 확장자에만 적용되어 `.php` 파일은 사각지대였습니다. 6종 모두 `**/*.php` 경로로 스코프되며, 안전 코드(prepared statement, `$wpdb->prepare()`, 상수 include 등) 오탐 0을 테스트로 검증했습니다.
  - `php-sql-concat` — `mysqli_query()`/`$wpdb->query()` 등에 `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`를 직접 연결·보간(SQL 주입, CWE-89). CRITICAL.
  - `php-unserialize-user-input` — 요청 입력을 `unserialize()`(PHP object injection, CWE-502). CRITICAL.
  - `php-include-user-input` — 요청 입력 기반 `include`/`require`(LFI/RFI, CWE-98). CRITICAL.
  - `php-exec-user-input` — 요청 입력이 들어간 `exec`/`system`/`shell_exec`/`passthru`(OS 명령 주입, CWE-78). CRITICAL.
  - `php-eval-usage` — PHP `eval()` 사용(CWE-95). HIGH.
  - `wordpress-debug-enabled` — `WP_DEBUG` true(프로덕션 정보 노출, CWE-489). WARNING.
- AWS CloudFormation 템플릿 misconfiguration 룰팩 `scanner/rules/cloudformation.yml`을 추가했습니다(정밀 룰 6종, YAML/JSON/`.template` 대상). Terraform-AWS는 기존 엔진이 커버하지만 raw CFN 템플릿은 공백이었습니다. 모든 패턴을 CFN 고유 컨텍스트(`AWS::` 리소스 타입, PascalCase 속성명)에 앵커링해 Kubernetes 매니페스트·docker-compose·GitHub Actions 워크플로 같은 YAML 유사 파일에서는 발화하지 않음을 테스트로 검증했습니다.
  - `cfn-iam-policy-star-star` — IAM 정책이 `Action`·`Resource` 모두 와일드카드(사실상 계정 전체 관리자 권한). Statement 경계를 넘는 오탐 차단. CRITICAL.
  - `cfn-s3-bucket-public-acl` — S3 버킷 `AccessControl`이 PublicRead/PublicReadWrite(전 세계 공개). HIGH.
  - `cfn-security-group-open-world` — 보안 그룹 ingress가 `0.0.0.0/0`·`::/0`에 개방(기본값인 open egress는 오탐 없이 통과). HIGH.
  - `cfn-rds-publicly-accessible` — `PubliclyAccessible: true`(DB 인스턴스 인터넷 직접 노출). HIGH.
  - `cfn-storage-unencrypted` — RDS `StorageEncrypted: false` 또는 EBS 볼륨 `Encrypted: false`(저장 데이터 미암호화). HIGH.
  - `cfn-secret-parameter-default` — 시크릿 성격 이름의 Parameter에 리터럴 `Default` 값 커밋(`{{resolve:...}}` 동적 참조는 안전으로 통과). HIGH.
- `tests/test_cloudformation_rules.py` — 룰별 양성/음성 패턴 테스트, severity 검증, e2e 스캔(오염 템플릿에서 6종 전부 발화, 안전 템플릿 0건), k8s/compose/GitHub Actions look-alike 음성 테스트 포함(총 29건).

### 추가
- Vue/Svelte/Nuxt 프런트엔드 룰 팩 `scanner/rules/vue-svelte.yml` 6종 추가(고정밀, 경로 스코프 적용). React(`dangerouslySetInnerHTML`)만 다루던 프런트엔드 XSS·시크릿 노출 탐지를 Vue·Svelte 생태계로 확장합니다.
  - `vue-v-html-usage` — `.vue` 템플릿의 `v-html` 디렉티브(raw HTML 렌더링, XSS 싱크). HIGH.
  - `svelte-html-tag-usage` — `.svelte` 템플릿의 raw HTML 태그(이스케이프 없이 마크업 주입). HIGH.
  - `nuxt-public-env-secret` — 시크릿 성격 이름의 환경 변수에 NUXT_PUBLIC_ 접두사 사용(클라이언트 번들에 노출). CRITICAL.
  - `vite-env-secret-exposed` — `.env*` 파일에서 시크릿 성격 이름의 변수에 VITE_ 접두사 사용(Vite가 클라이언트 번들에 인라인). CRITICAL.
  - `sveltekit-private-env-in-client` — `.svelte` 컴포넌트에서 SvelteKit private env(`$env/*/private`) import. HIGH.
  - `sveltekit-csrf-origin-check-disabled` — svelte.config에서 CSRF origin 검사 비활성화. HIGH.
  - `tests/test_vue_svelte_rules.py`: 룰별 양성·음성 정밀도, severity, 경로 스코프, e2e 스캔(취약/안전 프로젝트) 검증.
- Kotlin / Android 네이티브 룰 팩 `scanner/rules/kotlin-android.yml` — `.kt`/`.kts` 소스 전용 고정밀 룰 6종을 추가했습니다. 기존 팩이 다루지 않던 Kotlin 소스 사각지대를 메우며, `paths.include`로 Kotlin 파일에만 적용되어 다른 스택에 오탐을 만들지 않습니다.
  - `kotlin-webview-universal-file-access` — WebView `allowUniversalAccessFromFileURLs`/`allowFileAccessFromFileURLs` 활성화(로컬 파일 탈취 경로). CRITICAL.
  - `kotlin-sql-injection-raw` — `rawQuery`/`execSQL`에 문자열 템플릿(`$var`) 또는 `+` 연결로 SQL 조립. CRITICAL.
  - `kotlin-hardcoded-encryption-key` — `SecretKeySpec("리터럴".toByteArray(...))`로 암호화 키를 APK에 하드코딩. CRITICAL.
  - `kotlin-trust-all-certs` — `checkServerTrusted` 빈 구현(모든 TLS 인증서 수용, MITM 허용). HIGH.
  - `kotlin-world-accessible-prefs` — `MODE_WORLD_READABLE`/`MODE_WORLD_WRITEABLE` 사용(타 앱에 데이터 노출). HIGH.
  - `kotlin-log-sensitive-data` — `Log.*`에 password/token/secret 값 로깅(logcat 유출). WARNING.
  - 검증: `tests/test_kotlin_android_rules.py` — 룰별 양성/음성, severity, Kotlin 경로 스코핑, `_scan_file` end-to-end(발화·비발화) 테스트 18건.
- Electron 데스크톱 앱 보안 룰 팩 `scanner/rules/electron.yml` 추가(6종, 고정밀 — Electron 전용 식별자에 앵커링해 일반 웹 코드 오탐 0 검증):
  - `electron-node-integration-enabled` — renderer에서 nodeIntegration 활성화(XSS가 곧 RCE로 확대). CRITICAL.
  - `electron-context-isolation-disabled` — contextIsolation 비활성화(preload·특권 API 오염 가능). CRITICAL.
  - `electron-web-security-disabled` — webSecurity 비활성화(same-origin policy 해제, file:// 읽기 가능). HIGH.
  - `electron-allow-running-insecure-content` — HTTPS 페이지에서 HTTP 스크립트 실행 허용(mixed content 주입). HIGH.
  - `electron-shell-openexternal-user-input` — `shell.openExternal`에 비리터럴(동적) 인자 전달(임의 프로토콜·실행 파일 구동 위험). HIGH.
  - `electron-remote-module-enabled` — deprecated remote 모듈 활성화(renderer 침해 영향 확대). WARNING.
- `tests/test_electron_rules.py` — 룰별 양성/음성 정밀도, severity, 확장자 비제한(generic) 검증과 취약/하드닝된 Electron main 프로세스·비-Electron 코드 e2e 스캔 테스트를 추가했습니다.
- `appguardrail diff-report <old.json> <new.json>` — 두 `scan --findings-json` 스냅샷을 비교해 **해결됨/신규/잔존**을 마크다운으로 렌더링합니다("나아지고 있는가?"에 대한 바이어·감사 증거). 지문은 control plane의 drift 키(rule+file+message 앞부분)와 동일해 라인만 이동한 finding은 잔존으로 분류됩니다(해결+신규 중복 아님). 회귀/개선/진행 중/변화 없음 판정을 상단에 표시하며 `--out`으로 파일 저장이 가능합니다. 무의존성.
- C#/ASP.NET 탐지 룰 팩 `scanner/rules/dotnet.yml` 추가 — 기존 룰이 다루지 않던 `.cs`/`.cshtml`/`appsettings*.json`/`web.config` 사각지대를 커버합니다(고정밀, 안전 코드 오탐 0 검증).
  - `dotnet-sql-injection-concat` — `SqlCommand`/`ExecuteSqlRaw`/`FromSqlRaw`에 문자열 연결·보간으로 SQL을 조립. CRITICAL(CWE-89).
  - `dotnet-binaryformatter-deserialize` — `BinaryFormatter` 계열(SoapFormatter, NetDataContractSerializer, LosFormatter, ObjectStateFormatter) 사용. 신뢰할 수 없는 데이터 역직렬화 시 RCE. CRITICAL(CWE-502).
  - `dotnet-process-start-user-input` — `Process.Start`/`ProcessStartInfo`/`Arguments`에 연결·보간으로 명령줄 조립. CRITICAL(CWE-78).
  - `aspnet-request-validation-disabled` — `ValidateRequest="false"` 또는 `[ValidateInput(false)]`로 요청 검증 비활성화. HIGH(CWE-79).
  - `dotnet-cookie-secure-false` — `CookieSecurePolicy.None`, `Secure = false`, `requireSSL="false"` 등 Secure 플래그 없는 쿠키. HIGH(CWE-614).
  - `appsettings-connectionstring-password` — `appsettings*.json`/`web.config` 연결 문자열의 리터럴 `Password=`(플레이스홀더 `${…}`/`{0}`/`%…%`는 제외). HIGH(CWE-798). 스니펫은 자동 마스킹됩니다.

### 검증
- `tests/test_dotnet_rules.py`: 룰별 양성·음성 케이스, severity, 경로 스코핑(`**/*.cs` 등), `_scan_file` end-to-end 탐지, 시크릿 스니펫 마스킹 테스트를 추가했습니다. 시크릿 형태 픽스처는 런타임에 조립해 리터럴로 커밋하지 않습니다.

### 추가
- Go 보안 룰 팩 `scanner/rules/go.yml` — 기존 스캐너가 커버하지 않던 `.go` 파일을 경로 스코프(`**/*.go`) 기반으로 탐지합니다(고정밀, 안전 코드 오탐 0 검증):
  - `go-sql-injection-sprintf` — `Query`/`QueryRow`/`Exec`(+Context)에 `fmt.Sprintf` 또는 문자열 연결로 만든 SQL을 전달. CRITICAL.
  - `go-command-injection` — `exec.Command(Context)`가 `sh`/`bash` `-c`에 리터럴이 아닌(변수·연결) 명령 문자열을 전달. CRITICAL.
  - `go-hardcoded-jwt-signing-key` — `SignedString([]byte("리터럴"))`로 JWT 서명 키 하드코딩. CRITICAL.
  - `go-tls-insecure-skip-verify` — `tls.Config`의 `InsecureSkipVerify: true`(인증서 검증 비활성화). HIGH.
  - `go-weak-random-token` — token/secret/OTP/session 등 보안 값 생성에 `math/rand` 사용. HIGH.
  - `go-pprof-import-exposed` — `_ "net/http/pprof"` blank import로 기본 mux에 프로파일링 핸들러 노출. WARNING.
- `tests/test_go_rules.py` — 룰별 양성·음성 케이스, severity, `.go` 경로 스코프, 임시 파일 end-to-end 스캔 검증을 추가했습니다.
- **pre-commit 프레임워크 통합**(`.pre-commit-hooks.yaml`, 리포지토리 루트) — https://pre-commit.com 사용자 리포가 `.pre-commit-config.yaml`에 3줄만 추가하면 커밋마다 AppGuardrail 스캔이 실행되고, deploy-blocking 발견 시 커밋이 차단됩니다. 기존 `appguardrail hook`(직접 git hook 설치)과 상호 보완적입니다.
- `.appguardrailignore`(선택) — 스캔 루트에 gitignore 스타일 glob(한 줄당 하나, `#` 주석)을 두면 vendored 코드·생성물·서드파티 번들을 스캔에서 제외합니다. 이름만 쓰면(`vendor/`) 트리 어디서든 매칭되고, `*.min.js` 같은 glob·`docs/generated` 같은 경로도 지원합니다. 제외 건수를 스캔 출력에 표시해 조용히 빠지는 일이 없습니다.
- Ruby on Rails 보안 룰 팩 `scanner/rules/rails.yml` — 내장 룰이 다루지 않던 `.rb`/`.erb` 소스를 경로 글롭으로 스코핑해 탐지합니다. 모든 인젝션 룰은 실제 Ruby 문자열 보간(`#{...}`)이나 명백히 위험한 API를 요구하는 고정밀 설계로, 파라미터 바인딩 등 안전한 Rails 관용구는 매치하지 않습니다(안전 코드 오탐 0 검증).
  - `rails-sql-injection-interpolation` — `where`/`find_by_sql`/`order` 등에 보간 문자열로 SQL 조립(CWE-89). CRITICAL.
  - `rails-command-injection` — `system`/`exec`/`IO.popen`/`Open3.*`의 보간 문자열 셸 실행, `params`·`request`를 보간한 백틱 실행(CWE-78). CRITICAL.
  - `rails-secrets-in-code` — `secret_key_base` 하드코딩(세션 서명 키 유출로 세션 위조 가능, CWE-798). CRITICAL.
  - `rails-raw-html-output` — `raw(...)`/`.html_safe`로 HTML 이스케이프 우회 출력(XSS, CWE-79). HIGH.
  - `rails-mass-assignment-permit-all` — `params.permit!` 전체 파라미터 허용(대량 할당, CWE-915). HIGH.
  - `rails-skip-csrf` — `skip_before_action :verify_authenticity_token`으로 CSRF 보호 해제(CWE-352). HIGH.
- CI/CD 보안 탐지 룰 3종(`scanner/rules/cicd.yml`) — GitHub Actions 공급망/파이프라인 위험: `github-action-mutable-ref`(action을 @main/@master 이동 브랜치에 고정), `github-actions-pull-request-target`(fork PR 컨텍스트에서 secrets 접근), `github-actions-script-injection`(공격자 제어 `github.event.*`를 표현식에 인라인). 각각 SHA 고정·트리거 검토·env 경유 참조를 권고합니다.
- **GitHub Actions 네이티브 대응** — 스캔이 Actions 안에서 실행되면(`GITHUB_ACTIONS=true`) 자동으로 (1) 발견 항목을 PR diff에 인라인으로 띄우는 워크플로 어노테이션(`::error`/`::warning`, deploy-blocking은 error)과 (2) 실행 화면의 job summary(`$GITHUB_STEP_SUMMARY`, severity 집계 + 상위 목록)를 출력합니다. 로컬에서 강제하려면 `scan --github`. 무의존성(stdlib)이며 어노테이션 이스케이프는 GitHub 규격(`%0A`·`%2C`·`%3A`)을 따릅니다. 기존 `monitor` 워크플로는 변경 없이 인라인 표시를 얻습니다.
- **재사용 가능한 GitHub Action**(`action.yml`, 리포지토리 루트) — `uses: ContextualWisdomLab/appguardrail@v1` 한 줄로 스캔 + SARIF 업로드 + PR 코멘트 + deploy 게이트를 실행합니다. 입력 `path`·`sarif`·`upload-sarif`·`pr-comment`·`fail-on-blocking`·`version`, 출력 `sarif`·`exit-code`. composite action이라 별도 러너 이미지가 필요 없습니다.
- **PR 스티키 코멘트** — Actions의 `pull_request` 이벤트에서 발견 요약(severity 집계 + 상위 목록)을 PR에 단일 코멘트로 upsert합니다(매 푸시마다 새 코멘트가 아니라 기존 코멘트를 갱신 → 코멘트 스팸 없음). 숨은 마커로 식별하며 `GITHUB_TOKEN`만 사용합니다(무의존성 urllib). 코멘트 실패는 보안 게이트를 절대 실패시키지 않습니다.
- `appguardrail fix` 명령 — 안전하고 결정적인 자동 수정을 적용합니다(기본 dry-run diff, `--apply`로 기록). 의미를 바꾸지 않는 순수 additive 변환만 수행하며, 첫 변환으로 외부 `target="_blank"` 링크에 `rel="noopener noreferrer"`를 추가합니다(reverse tabnabbing 방지). 동작을 바꾸는 수정(시크릿→env 등)은 위험하므로 자동 적용하지 않고 fix-pack 프롬프트로 남깁니다. scan→fix→verify 루프를 안전하게 닫습니다.
- `appguardrail serve` — 멀티테넌트 **control-plane API**(스캔 인제스트 + 히스토리). 일회성 CLI를 넘어, CI가 매 스캔의 `appguardrail.findings.v1`을 org별 API 키로 영속 저장하고 시간에 따른 추이를 조회할 수 있는 지속형 백본입니다. stdlib(sqlite3 + http.server)만 사용하며 org별 테넌트 격리를 강제합니다.
  - 엔드포인트: `POST /api/v1/scans`(인제스트), `GET /api/v1/scans`(히스토리), `GET /api/v1/scans/{id}`(상세), `GET /api/v1/health`.
  - 인증: `Authorization: Bearer <api_key>`. `--create-org <name>`으로 org·키 발급, 빈 DB면 기본 org를 부트스트랩합니다.
  - **org console** — control-plane 서버가 `/`에서 서빙하는 단일 정적 페이지(`scanner/dashboard/console.html`). API 키로 연결해 스캔 히스토리, deploy-blocking 추이, 스캔 상세를 봅니다(프레임워크·빌드 단계 없음).
  - **drift 감지** — 인제스트 시 같은 org+repo의 직전 스캔 대비 **신규 deploy-blocking** 수(`new_blocking`)를 계산합니다(line-독립 지문). console과 API 응답에 노출됩니다.
  - **API 페이지네이션 + trend** — `GET /api/v1/scans?limit=&offset=`로 스캔 히스토리를 페이징하고, `GET /api/v1/scans/trend?limit=`로 시간순(오래된→최신) deploy_blocking·new_blocking 시계열을 얻습니다(차트용).
  - **RBAC / 멀티유저** — org별 다중 API 키에 역할(viewer/member/owner)을 부여합니다. viewer=읽기, member=스캔 인제스트, owner=webhook·키 발급 포함 전체. `POST /api/v1/keys`(owner)로 역할 지정 키를 발급합니다. 부트스트랩 키는 owner입니다.
  - **drift 알림 webhook** — org에 webhook URL을 설정하면(`POST /api/v1/webhook`) `new_blocking > 0`인 스캔에서 알림을 POST합니다(best-effort, 인제스트 실패 안 함). detect→alert 루프를 닫습니다.
  - **Slack 포맷 drift 알림** — webhook 호스트가 `hooks.slack.com`이면 payload를 Slack Block Kit 메시지(헤더 + org·신규 blocker 수·repo·scan, 상위 5개 `rule_id`/파일 목록과 `+N more` 오버플로)로 자동 렌더링해 Slack Incoming Webhook이 읽기 좋은 카드로 표시합니다. 그 외 URL은 기존 generic JSON payload를 그대로 받습니다(하위 호환). 무의존성 유지를 위해 stdlib만 사용하며 텍스트는 이스케이프·트림합니다.
  - `appguardrail scan --push <url>` — 스캔 후 findings를 control-plane에 POST합니다(키는 `APPGUARDRAIL_API_KEY`, repo/commit은 `GITHUB_REPOSITORY`/`GITHUB_SHA`에서 자동). CI가 매 스캔을 플랫폼에 밀어넣어 continuous-monitoring 루프를 닫습니다.
  - `appguardrail monitor` 워크플로가 `APPGUARDRAIL_CONTROL_PLANE_URL` secret이 설정된 경우 스캔을 control-plane에 자동 push합니다(`APPGUARDRAIL_API_KEY` secret 사용). 미설정 시 기존 SARIF+게이트 동작 그대로.
- `appguardrail sbom` — 의존성 매니페스트(npm `package-lock.json`/`package.json`, Python `requirements.txt`)에서 CycloneDX 1.5 SBOM을 생성합니다. 무의존성(stdlib)으로 동작하며, lockfile이 있으면 resolved 버전을, 없으면 매니페스트의 declared 범위를 사용하고 컴포넌트 properties에 출처를 기록합니다. 공급망 실사(due diligence)의 기본 산출물입니다.
- `appguardrail sbom`의 lockfile 파서를 확장했습니다 — `poetry.lock`(pypi), `pnpm-lock.yaml`·`yarn.lock`(npm)을 추가로 인식합니다. 서드파티 toml/yaml 라이브러리 없이 stdlib만으로 손수 파싱하며(정규식·라인 스캔), scoped npm 패키지(`@scope/name`)·pnpm peer-dependency 접미사·yarn 다중 spec 헤더를 처리하고 resolved 버전으로 기록합니다. npm 측은 `package-lock.json` > `pnpm-lock.yaml` > `yarn.lock` > `package.json` 순으로 우선하고, `poetry.lock`은 Python 측에 additive로 더해집니다.

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
- 제공자별 고정밀 시크릿 탐지 룰 6종 추가(distinctive prefix 기반, 안전 코드 오탐 0 검증):
  - `hardcoded-slack-token`(xoxb/xoxa/xoxp/… Slack 토큰), `hardcoded-twilio-credential`(Twilio Account SID `AC…`/API key `SK…`), `hardcoded-sendgrid-api-key`(`SG.` SendGrid 키), `hardcoded-npm-token`(`npm_` npm 토큰), `hardcoded-pypi-token`(`pypi-AgEIcHlwaS…` PyPI 토큰) — 모두 CRITICAL.
  - `hardcoded-slack-webhook-url`(`hooks.slack.com/services/…` incoming webhook) — HIGH.
  - 모든 룰에 `cwe: [CWE-798]`, `owasp: [A07:2021]` 부여. 기존 룰(OpenAI/Anthropic/Stripe/AWS/GitHub/Google/PEM)과 중복 없음.
- Java/Spring 보안 룰팩 `scanner/rules/java-spring.yml` 추가(고정밀 5종, 내장 Java 룰과 중복 없음):
  - `java-sql-injection-concat` — `createQuery`/`prepareStatement`/`executeQuery`에 문자열 리터럴 + 변수 연결로 SQL/JPQL 조립. CRITICAL.
  - `java-runtime-exec-concat` — `Runtime.getRuntime().exec`/`ProcessBuilder`에 문자열 연결로 OS 명령 조립. CRITICAL.
  - `java-xxe-unsafe-parser` — 외부 엔티티/DTD를 명시적으로 허용하는 XML 파서 설정(`external-*-entities=true`, `disallow-doctype-decl=false`, `SUPPORT_DTD=true`). HIGH.
  - `java-trustall-trustmanager` — `checkServerTrusted` 본문이 비어 있는 trust-all `X509TrustManager`(TLS 검증 무력화). HIGH.
  - `spring-actuator-exposed` — `management.endpoints.web.exposure.include=*`(properties·yml 중첩 표기 모두 탐지, `application*` 설정 파일로 경로 스코프). HIGH.

### 추가
- `appguardrail scan --sarif <path>` — 정규화된 findings를 SARIF 2.1.0으로 출력합니다. GitHub code scanning(`github/codeql-action/upload-sarif`), VS Code SARIF viewer, Azure DevOps 등 SARIF 소비 도구가 그대로 읽어 Security tab 알림·PR 인라인 주석으로 표시됩니다. severity→level 매핑과 GitHub 랭킹용 `security-severity` 속성, deploy-gate 의미(`deployBlocking`), 재실행 간 안정적인 `partialFingerprints`를 포함합니다.
- `appguardrail monitor`가 설치하는 워크플로가 이제 SARIF를 생성해 GitHub code scanning에 업로드합니다(`security-events: write`). deploy 게이트는 그대로 유지됩니다.
- `appguardrail dashboard` 명령을 추가했습니다. `scan --findings-json`이 생성한 `appguardrail.findings.v1` 파일을 로컬 웹 대시보드로 렌더링합니다. severity 요약, deploy-blocking 게이트, 카테고리별 findings, 그리고 finding별 상세(AppGuardrail Fix Format: Problem / Fix Prompt / Verification)를 보여줍니다.
  - 옵션: `--findings`, `--port`, `--host`, `--no-open`.
  - 대시보드는 프레임워크·빌드 단계가 없는 단일 정적 페이지(`scanner/dashboard/index.html`)이며, wheel에 포함되어 `pip install` 설치본에서도 동작합니다.
  - findings 파일을 `/findings.json`으로 직접 서빙하여 실행 위치(cwd)와 무관하게 로드됩니다.

### 검증
- `tests/test_rails_rules.py`: 룰별 positive/negative 스니펫·severity 검증, 임시 Rails 앱 파일 대상 end-to-end 스캔 발화 테스트, 그리고 안전한 컨트롤러와 비 Ruby 경로에서는 침묵하는지 확인하는 테스트를 추가했습니다.
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
