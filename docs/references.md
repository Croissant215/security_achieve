# 참고 자료와 의존성

## 구현 참고

- [Flask 설치 문서](https://flask.palletsprojects.com/en/stable/installation/): 가상환경, 개발 서버, 의존성 구성.
- [Python sqlite3](https://docs.python.org/3/library/sqlite3.html): 메모리 DB, 바인딩, authorizer, 실행량 제한. 방어 경로는 값을 SQL과 분리해 전달한다.
- [Werkzeug 비밀번호 해시](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.generate_password_hash): scrypt 저장·검증.
- [MDN iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe): `sandbox="allow-scripts"`로 스크립트 실행과 주 화면 접근 권한을 분리한다. `allow-same-origin`은 부여하지 않는다.
- [shadcn/ui](https://ui.shadcn.com/docs/components/base/button): MCP로 button·table 정보와 tabs 예제를 확인했다. 상태·간격·의미 기반 토큰을 참고했고, React 컴포넌트 코드를 배포 파일에 복사하거나 React를 설치하지 않았다.
- 로컬 UI/UX Pro Max와 anti-ui-slop: 접근성, 상태 표현, 반응형, 실제 화면 검증 기준.

기존 `Vibe_Coding` 소스는 복사하지 않았다. 이번 요구사항에 맞춰 두 실습을 새로 구현했다. 화면의 CSS·JavaScript·SVG는 프로젝트 안에 포함되며 외부 폰트·이미지 CDN을 사용하지 않는다.

## 패키지 출처

실행 의존성은 `requirements.txt`, 개발 검사 의존성은 `requirements-dev.txt`에 기록했다. 패키지는 원본 배포판을 설치하며 각 패키지의 라이선스·고지를 유지한다. 설치된 배포판의 `*.dist-info/licenses` 또는 `LICENSE*`에서 고지를 확인할 수 있다.

| 패키지 | 출처 | 라이선스 |
|---|---|---|
| Flask | https://github.com/pallets/flask | BSD-3-Clause |
| Werkzeug | https://github.com/pallets/werkzeug | BSD-3-Clause |
| Jinja2 | https://github.com/pallets/jinja | BSD-3-Clause |
| MarkupSafe | https://github.com/pallets/markupsafe | BSD-3-Clause |
| ItsDangerous | https://github.com/pallets/itsdangerous | BSD-3-Clause |
| Click | https://github.com/pallets/click | BSD-3-Clause |
| Blinker | https://github.com/pallets-eco/blinker | MIT |
| Playwright (검사 전용) | https://github.com/microsoft/playwright-python | Apache-2.0 |

프로젝트 자체 소스의 공개 라이선스는 아직 선택하지 않았다. 최종 공개·제출 전에 저장소 소유자가 결정한다.
