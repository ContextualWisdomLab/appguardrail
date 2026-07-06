# 변경 사항

## 성능 최적화 (Performance Improvements)
- `_scan_file` 내부에서 `pathlib.Path.relative_to` 호출을 단순한 문자열 `startswith` 검사로 대체하여 성능 개선 (약 150배 속도 향상). 이를 통해 파일 검색이 빈번하게 수행되는 환경에서 큰 성능 이점을 얻을 수 있습니다.

