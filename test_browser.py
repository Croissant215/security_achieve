"""Real browser checks, using a temporary DB and an ephemeral loopback server."""
from pathlib import Path
import sys
import tempfile
import threading

from playwright.sync_api import sync_playwright, expect
from werkzeug.serving import make_server

from app import create_app


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    artifacts = Path('artifacts')
    artifacts.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as folder:
        server = make_server('127.0.0.1', 0, create_app(Path(folder) / 'browser.sqlite3'), threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(channel='msedge', headless=True)
                page = browser.new_page(viewport={'width': 1440, 'height': 1000})
                page.set_default_timeout(15000)
                errors, external = [], []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else (external.append(route.request.url), route.abort()))
                page.goto(base)
                expect(page.locator('#run')).to_be_enabled()
                page.screenshot(path=str(artifacts / 'desktop.png'), full_page=True)
                page.locator('#run').click()
                expect(page.locator('#output-vulnerable')).to_contain_text('로그인 성공')
                with page.expect_popup() as popup:
                    page.get_by_role('link', name='실습용 회원 페이지 열기').click()
                expect(popup.value.locator('h1')).to_contain_text('student')
                popup.value.close()
                page.get_by_role('button', name='로그인 우회', exact=True).click()
                expect(page.locator('#comparison-note')).to_contain_text('입력이 변경')
                page.locator('#run').click()
                expect(page.locator('#output-vulnerable')).to_contain_text('admin')
                page.locator('#defend').click()
                expect(page.locator('#username')).to_have_value("admin' --")
                page.locator('#run').click()
                expect(page.locator('#output-secure')).to_contain_text('로그인 실패')
                expect(page.locator('#comparison-note')).to_contain_text('같은 입력')
                page.locator('#verify').click()
                expect(page.locator('#verify-status')).to_contain_text('6/6 통과')
                assert page.locator('#verification-body .state-pass').count() == 6
                page.locator('#defend').click()
                expect(page.locator('#mode-badge')).to_contain_text('취약')
                expect(page.locator('#username')).to_have_value("admin' --")
                print('SQL browser cases: 6/6, defense switch, input tracking, member page OK')

                page.locator('[data-lesson=xss]').click()
                page.get_by_role('button', name='실습용 스크립트', exact=True).click()
                page.locator('#run').click()
                expect(page.locator('#output-vulnerable')).to_contain_text('실습 스크립트 실행됨')
                frame = page.frame_locator('#output-vulnerable iframe')
                expect(frame.locator('#signal')).to_have_text('[스크립트 실행됨]')
                page.locator('#defend').click()
                page.locator('#run').click()
                expect(page.locator('#output-secure')).to_contain_text('실행 신호 없음')
                expect(page.frame_locator('#output-secure iframe').locator('#post-body')).to_have_text('<script>labSignal()</script>')
                page.locator('#verify').click()
                expect(page.locator('#verify-status')).to_contain_text('6/6 통과')
                assert page.locator('#verification-body .state-pass').count() == 6
                page.evaluate('scrollTo(0, 0)')
                page.screenshot(path=str(artifacts / 'xss-comparison.png'), full_page=True)
                print('XSS browser cases: 6/6, real execution signal and escaped output OK')
                page.locator('#verify').click()
                expect(page.locator('#verify-status')).to_contain_text('6/6 통과')
                page.locator('#reset').click()
                page.locator('#confirm-reset').click()
                expect(page.locator('#tag-vulnerable')).to_have_text('실행 전')
                expect(page.locator('#log-count')).to_have_text('0건')
                expect(page.locator('#body')).to_have_value('안녕하세요')
                print('Repeat verification and reset OK')

                # Logs must treat HTML as text, even in the intentionally vulnerable lab.
                page.locator('#body').fill('<script>try {parent.document.body.dataset.leaked="yes"} catch(e) {labSignal()}</script>')
                page.locator('#run').click()
                expect(page.locator('#tag-vulnerable')).to_have_text('실행 완료')
                assert page.locator('body').get_attribute('data-leaked') is None
                assert page.locator('#log-list script').count() == 0
                expect(page.locator('#output-vulnerable')).to_contain_text('실습 스크립트 실행됨')
                print('Sandbox blocks parent DOM access; logs render input as text')

                # A JS exception is an error, never an apparent defense success.
                page.locator('#body').fill('<script>throw new Error("test")</script>')
                page.locator('#run').click()
                expect(page.locator('#tag-vulnerable')).to_have_text('오류')
                expect(page.locator('#output-vulnerable')).to_contain_text('판정할 수 없습니다')
                errors.clear()  # The previous sandbox exception was intentional.

                page.locator('[data-lesson=sql]').click()
                for width in (375, 768, 1024, 1440):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), f'Overflow at {width}px'
                    if width == 375:
                        page.screenshot(path=str(artifacts / 'mobile.png'), full_page=True)
                assert not errors, errors
                assert not external, external
                print('375/768/1024/1440px: no page overflow; no external requests or unexpected page errors')
                browser.close()
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
