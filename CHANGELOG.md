# 변경 사항 (CHANGELOG)

## [Unreleased]

### 추가
- `scanner/cli/vibesec.py`의 100% 테스트 커버리지를 달성하기 위해 `tests/test_vibesec_coverage.py` 테스트 파일을 추가했습니다.
  - `cmd_init`: `claude-code` 사용 시 `append_marker` 관련 파일 생성 및 심볼릭 링크 예외, 경로 이탈(`path traversal`) 방지 테스트 추가.
  - `cmd_scan`: 존재하지 않는 경로 및 심볼릭 링크 경로 스캔 시 예외 처리 테스트 추가.
  - `cmd_hook`: `.git` 디렉토리 부재 시 에러 반환, 훅 스크립트의 정상 설치, 심볼릭 링크 처리 및 경로 이탈 방지 테스트 추가.
  - 파일 시스템 IO: 파일 디렉토리 순회(`_collect_files`) 시 `os.scandir` 및 하위 노드의 `OSError` 처리 테스트 추가. 파일 정보 획득(`os.lstat`) 과정의 권한 및 예외(`OSError`) 처리 테스트 추가.
  - `cmd_review`: `--stack`, `--db`, `--payments` 인자 유무에 따른 프롬프트 생성 분기 테스트 추가.
  - `main` 함수: 터미널 인자(args) 파싱 및 서브 커맨드(`init`, `scan`, `review`, `hook`) 호출, 그리고 인자가 없을 때의 예외 동작을 포함한 테스트 추가.
  - `if __name__ == '__main__':` 블록의 실행 테스트 추가.

### 변경
- `scanner/cli/vibesec.py` 전체 코드에 대한 테스트 커버리지 100% 달성 및 기존 기능의 안정성 확보 검증.
