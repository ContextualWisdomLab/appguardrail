# 변경 사항 (CHANGELOG)

## [Unreleased]

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

### 검증
- `scanner/cli/appguardrail.py` 전체 코드에 대한 테스트 커버리지 100% 달성 및 기존 기능의 안정성 확보 검증.
