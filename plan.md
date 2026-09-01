1. **`scanner/dashboard/console.html` 수정 (로딩 상태 의미론적 스타일링 적용 및 이벤트 가드 추가)**
   - `button:disabled` 및 `[aria-busy="true"]` 상태일 때 사용자가 시각적으로 비활성화되었음을 알 수 있도록 CSS에 `opacity: 0.7; pointer-events: none;` 속성을 추가합니다.
   - `tr.scan` 요소에 대해 클릭 및 키보드(엔터/스페이스) 이벤트 리스너에서 `aria-busy` 속성을 확인하여, `aria-busy="true"`일 경우 추가적인 `detail()` 호출을 방지하는(즉, 중복 요청 방지) 가드 로직을 추가합니다.
2. **테스트 및 검증 실행**
   - 코드를 수정한 후 의도대로 변경이 되었는지 브라우저나 도구를 이용해 시각적으로 또는 스크립트로 검증합니다.
   - 프로젝트의 테스트 명령어가 있다면(예: `pnpm test` 등) 이를 실행하여 변경 사항이 다른 기능을 망가뜨리지 않았는지 확인합니다.
3. **Pre-commit 점검 단계 수행**
   - `pre_commit_instructions` 도구를 호출하여 올바른 검증, 린트, 포매팅 등의 작업이 모두 완료되었는지 최종 점검합니다.
4. **변경 사항 제출(PR 생성)**
   - 코드 리뷰를 통과하면 변경 사항을 제출합니다. 커밋 제목은 "🎨 Palette: Add semantic disabled styles and event guards for async loading states" 와 같은 형태를 따르며, 설명에는 '무엇을', '왜', '접근성(Accessibility)'에 대한 내용을 한국어로 작성합니다.
