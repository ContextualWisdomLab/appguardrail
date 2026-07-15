## 2026-06-23 - Error message UX improvements
**Learning:** Error messages in CLIs should be explicit, use visual cues (like emojis for attention), and provide actionable hints when appropriate.
**Action:** When adding or modifying error messages in the CLI, use '❌ Error: [Message]' format and add '💡 Hint: [Actionable advice]' to help users resolve the issue easily.

## 2026-06-30 - Added Emojis to CLI Output Messages
**Learning:** Adding subtle emojis to informative CLI output headers (like "Created/updated files" and "Next steps") provides clearer visual cues for developers scanning long CLI output.
**Action:** Always include relevant emojis in summary output text to make success and informational messages more visually distinguishable from routine command logs.

## 2024-07-08 - Conditionally disable CLI emojis
**Learning:** Heavy emoji usage in CLI tools can degrade accessibility for screen readers and cause issues in non-UTF8 terminals or log parsers.
**Action:** Implemented a targeted regex filter toggled by `APPGUARDRAIL_NO_EMOJI` to gracefully degrade CLI output without stripping valid international text, improving overall CLI UX and accessibility.

## 2026-07-06 - Clickable table rows and keyboard navigation
**Learning:** Treating standard `<tr>` elements as interactive clickable rows means they are ignored by screen readers and keyboard users unless specifically configured. Users relying on keyboards couldn't access finding details.
**Action:** When making custom non-interactive elements (like table rows or divs) clickable, always add `tabindex="0"`, a semantic `role="button"`, appropriate ARIA labels, and explicit `keydown` listeners for 'Enter' and 'Space' to support full accessibility.

<<<<<<< HEAD
## 2026-07-13 - Native HTML <dialog> Accessibility
**Learning:** The native HTML `<dialog>` element via `showModal()` does not automatically restore focus to the previously active element upon closing. Keyboard users may lose their position in the tab order, severely degrading the experience (e.g. when opening a detailed view from a table).
**Action:** When using `<dialog>`, capture `document.activeElement` before opening the modal and restore focus to it via an event listener attached to the `close` event. Also, ensure there is an explicit backdrop click-to-close event listener.
=======
## 2026-07-28 - Native HTML dialog accessibility and UX
**Learning:** Native HTML `<dialog>` elements do not automatically restore focus to the triggering element upon closure or close when the backdrop is clicked. This significantly breaks keyboard navigation flow for screen readers and power users.
**Action:** When implementing or modifying `<dialog>` elements, always manually capture the `document.activeElement` before calling `showModal()`, and restore focus to it via a `'close'` event listener. Also, add a `'click'` listener to the dialog to close it if `e.target === dialog` to support standard backdrop click UX.
>>>>>>> origin/develop

## 2024-07-13 - CLI 출력의 영문법적 복수형 및 에러 메시지 힌트 개선
**Learning:** CLI 출력에서 `file(s)`, `issue(s)`, `rule(s) excluded`와 같이 괄호를 사용한 복수형 표기법은 가독성을 떨어뜨리고 투박한(developer-centric) 느낌을 줍니다. 또한, 에러 발생 시 단순 예외 내용만 출력하는 것보다 즉시 실행 가능한 해결책(Hint)을 함께 제공하는 것이 CLI 사용자 경험(DX) 향상에 매우 효과적입니다.
**Action:** 조건부 f-string(예: `s_suffix = "s" if count != 1 else ""`)을 활용하여 동적으로 정확한 복수형 단어(file/files)를 출력하도록 개선하고, 예외 발생 로직에는 항상 `💡 Hint:`를 포함하여 후속 액션을 안내하도록 표준화해야 합니다. (단, Python 3.12 환경의 `black` 포매터 호환성을 위해 백슬래시가 포함된 중첩 f-string 사용을 피하고 변수 추출을 권장합니다.)
## 2024-05-18 - Standardize CLI Error and Hint Messages
**Learning:** The CLI tool's DX is significantly improved when error messages follow a strict standard format `❌ Error: [Message]` and `💡 Hint: [Actionable advice]`. This makes console output highly scannable and guides users quickly to resolution without confusion.
**Action:** Always include the `Error:` and `Hint:` keywords directly after the respective emojis when writing or updating terminal output messages.
