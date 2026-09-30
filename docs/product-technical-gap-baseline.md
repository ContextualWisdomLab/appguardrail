# Product technical gap baseline

상태: **Proposed**  
최근 조정: 2026-09-30 UTC  
대상: [appguardrail#1361](https://github.com/ContextualWisdomLab/appguardrail/pull/1361)

이 문서는 제품의 도메인 진실을 대체하지 않는다. 대시보드는
`appguardrail.findings.v1`을 읽는 presentation adapter이며, finding과
reference의 의미·유효성·provenance는 scanner 계약이 소유한다.

## 현재 evidence

| Evidence | 기준 |
|---|---|
| PRD | `docs/PRD.md` |
| TRD | `docs/TRD.md` |
| UML | `docs/UML.md` |
| ERD | `docs/ERD.md` |
| Context Map | scanner → `appguardrail.findings.v1` → static dashboard; dashboard는 read-only consumer |
| protected base | `develop@2949d30718752ea5915c7713ba227e8c19d9e5bf` |
| RED contract | `d788534db17c1cc9e6fb7843a8f374b6f53ac84e` |
| product repair | `29a089a8363e6baf1f64ded48621a8d7dcb2eb06` |
| generator-note cleanup | `89678c81e9e802c3033fb1a13f07d0bfe92d824f` |
| exact current head | PR 본문의 exact-head matrix와 GitHub Checks를 최종 authority로 사용 |

## Gap / Action

| ID | Gap | Action / owner | 상태 |
|---|---|---|---|
| DA-1361-01 | 긴 URL에 `word-break:break-all`을 적용해 문자 단위 분절을 강제함 | AppGuardrail dashboard: `overflow-wrap:anywhere`와 회귀 계약 | **GREEN** |
| DA-1361-02 | 새 탭 안내가 영어 하드코딩이며 ko/en/ja/zh/vi/es/de/fr 계약이 없음 | product translation owner가 DB-backed screen-key 계약과 locale E2E 제공 | **FAIL / Proposed** |
| DA-1361-03 | current-head pointer/touch/keyboard 및 desktop/mobile/intermediate screenshot이 없음 | dashboard owner가 real-browser 증거와 WCAG 2.2 AA audit 첨부 | **FAIL / Proposed** |
| DA-1361-04 | loading/empty/error/offline/permission/read-only/stale/conflict/retry/busy 상태 matrix가 완전하지 않음 | 적용 가능한 상태를 정형 fixture와 E2E로 증명하고 N/A는 근거 기록 | **FAIL / Proposed** |
| DA-1361-05 | 대규모 findings에서 render/p95, heap, DOM 규모 증거가 없음 | 현실적 대용량 fixture로 profile하고 p95 ≤20ms 목표 검증 | **FAIL / Proposed** |
| DA-1361-06 | CodeQL compatibility consumer가 초기 head에서 current-head verdict를 찾지 못해 실패함 | `.github` owner가 dispatch/run linkage exact log와 재실행을 복구 | **FAIL / Proposed** |

## Exact-head acceptance matrix

PR은 아래 모든 applicable 항목이 current head에서 PASS가 되기 전 merge-ready가 아니다.

| 항목 | 현재 판정 | 근거 / 남은 acceptance |
|---|---|---|
| Determinism | PASS | static CSS/markup regression contract |
| Semantics | PASS (bounded) | `noopener`, visible cue, screen-reader warning 보존 |
| Accessibility | FAIL | 실제 keyboard/screen-reader/WCAG audit 없음 |
| Responsive evidence | FAIL | desktop/mobile/intermediate screenshots 없음 |
| Touch/pointer | FAIL | coarse/fine pointer 실브라우저 증거 없음 |
| 8 locales | FAIL | ko/en/ja/zh/vi/es/de/fr screen-key 계약 없음 |
| Large-data performance | FAIL | 현실적 findings 규모 측정 없음 |
| Import/export | PARTIAL | JSON file import 경로는 기존 기능; current-head recovery E2E 없음 |
| Recovery | FAIL | offline/error/retry/stale/conflict lifecycle 증거 없음 |
| Exact-head Checks | FAIL | 초기 head CodeQL compatibility failure; 새 head 재실행 필요 |

