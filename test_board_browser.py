"""Integrated website flow with real SQL authentication and sandboxed stored XSS."""
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
        server = make_server('127.0.0.1', 0, create_app(Path(folder) / 'test.sqlite3'), threaded=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(channel='msedge', headless=True)
                page = browser.new_page(viewport={'width': 1440, 'height': 1000})
                errors, external = [], []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else (external.append(route.request.url), route.abort()))
                page.goto(base)
                expect(page).to_have_url(base + '/board')
                page.screenshot(path=str(artifacts / 'first-use-desktop.png'), full_page=True)
                page.set_viewport_size({'width': 375, 'height': 900})
                page.screenshot(path=str(artifacts / 'first-use-mobile.png'), full_page=True)
                page.get_by_role('link', name='1단계 · 로그인하러 가기').click()
                page.get_by_role('button', name='정상 계정 입력', exact=True).click()
                expect(page.get_by_label('아이디', exact=True)).to_have_value('student')
                expect(page.get_by_label('실습 비밀번호', exact=True)).to_have_value('study1234')
                expect(page).to_have_url(base + '/board/login')
                page.get_by_role('button', name='로그인', exact=True).click()
                page.get_by_role('link', name='2단계 · 첫 글 작성하기').click()
                page.get_by_role('button', name='일반 글 예제 입력').click()
                expect(page.get_by_label('제목', exact=True)).to_have_value('처음 작성한 게시글')
                page.get_by_role('button', name='글 저장', exact=True).click()
                page.get_by_role('link', name='최근 글 열기 · 처음 작성한 게시글').click()
                expect(page.frame_locator('[data-mode=secure] iframe').locator('#post-body')).to_have_text('안녕하세요. 게시판에 글을 저장하고 다시 열어 봅니다.')
                page.get_by_role('link', name='결과 설명 보기').click()
                expect(page.locator('#learning-panel')).to_be_focused()
                expect(page.locator('.learning-panel .executed-code').first).not_to_be_visible()
                page.locator('.learning-panel').get_by_text('실행 코드 보기', exact=True).first.click()
                expect(page.locator('.learning-panel .executed-code').first).to_be_visible()
                page.get_by_role('link', name='글쓰기', exact=True).click()
                page.get_by_role('button', name='XSS 예제 입력', exact=True).click()
                expect(page.get_by_label('본문', exact=True)).to_have_value('<script>labSignal()</script>')
                expect(page).to_have_url(base + '/board/new')
                page.get_by_role('button', name='글 저장', exact=True).click()
                page.get_by_role('link', name='최근 글 열기 · 글을 열 때 실행되는 XSS 예제').click()
                page.get_by_role('button', name='같은 글 두 모드 비교').click()
                expect(page.locator('[data-mode=vulnerable] .observation')).to_contain_text('실습 스크립트 실행됨')
                expect(page.locator('[data-mode=secure] .observation')).to_contain_text('실행 신호 없음')
                page.get_by_role('button', name='로그아웃', exact=True).click()
                page.set_viewport_size({'width': 1440, 'height': 1000})
                page.get_by_role('link', name='글쓰기', exact=True).click()
                expect(page).to_have_url(base + '/board/login')
                page.get_by_role('button', name='틀린 비밀번호 입력').click()
                expect(page.get_by_label('실습 비밀번호', exact=True)).to_have_value('wrong')
                page.get_by_role('button', name='로그인 우회 예제 입력').click()
                expect(page.get_by_label('아이디', exact=True)).to_have_value("admin' --")
                page.get_by_role('radio', name='방어 코드', exact=True).check()
                page.get_by_role('button', name='같은 입력으로 두 모드 비교').click()
                expect(page.locator('[role=alert]')).to_contain_text('로그인 실패')
                expect(page.locator('.learning-panel')).to_contain_text('로그인 성공 · admin')
                expect(page.locator('.learning-panel')).to_contain_text('secure_login')
                expect(page.locator('.learning-panel')).to_contain_text('vulnerable_login')
                expect(page.locator('.board-account')).to_have_count(0)
                page.screenshot(path=str(artifacts / 'board-login-comparison.png'), full_page=True)
                page.get_by_role('radio', name='취약 코드', exact=True).check()
                page.get_by_role('button', name='같은 입력으로 두 모드 비교').click()
                expect(page.locator('.board-account')).to_have_text('admin 로그인 중')
                page.get_by_role('link', name='글쓰기', exact=True).click()
                page.get_by_label('제목', exact=True).fill('저장한 글을 열 때 실행되는 코드')
                payload = '<script>try {parent.document.body.dataset.leaked="yes"} catch(e) {labSignal()}</script>'
                page.get_by_label('본문', exact=True).fill(payload)
                page.get_by_role('button', name='글 저장', exact=True).click()
                expect(page.locator('.learning-panel')).to_contain_text('본문은 아직 브라우저에서 열지 않았습니다')
                expect(page.locator('iframe')).to_have_count(0)
                assert page.locator('.learning-panel script').count() == 0
                page.locator('.board-title').first.click()
                expect(page.locator('.board-byline')).to_contain_text('작성자 admin')
                expect(page.locator('.observation')).to_contain_text('실습 스크립트 실행됨')
                assert page.locator('body').get_attribute('data-leaked') is None
                page.get_by_role('button', name='같은 글 두 모드 비교').click()
                expect(page.locator('[data-mode=vulnerable] .observation')).to_contain_text('실습 스크립트 실행됨')
                expect(page.locator('[data-mode=secure] .observation')).to_contain_text('실행 신호 없음')
                expect(page.frame_locator('[data-mode=secure] iframe').locator('#post-body')).to_have_text(payload)
                expect(page.locator('[data-output-mode=secure] .output-state')).to_contain_text('실행 신호 없음')
                page.screenshot(path=str(artifacts / 'board-learning-desktop.png'), full_page=True)
                for width in (375, 768, 1024, 1440):
                    page.set_viewport_size({'width': width, 'height': 1000})
                    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), width
                    if width == 375:
                        page.locator('[data-mode=secure] iframe').scroll_into_view_if_needed()
                        expect(page.frame_locator('[data-mode=secure] iframe').locator('#post-body')).to_be_visible()
                        page.screenshot(path=str(artifacts / 'board-secure-mobile.png'))
                        page.screenshot(path=str(artifacts / 'board-learning-mobile.png'), full_page=True)

                # Dropped preview responses must become timeout, not defense success.
                page.route('**/preview/board/*', lambda route: route.abort())
                page.reload()
                expect(page.locator('[data-mode=secure] .observation')).to_contain_text('관찰 시간 초과', timeout=10000)
                page.unroute('**/preview/board/*')

                page.get_by_role('link', name='글쓰기', exact=True).click()
                page.get_by_label('제목', exact=True).fill('오류 관찰')
                page.get_by_label('본문', exact=True).fill('<script>throw new Error("board test")</script>')
                page.get_by_role('button', name='글 저장', exact=True).click()
                page.locator('.board-title').first.click()
                expect(page.locator('.observation')).to_contain_text('판정할 수 없습니다')
                assert errors and all('board test' in error for error in errors), errors
                errors.clear()
                page.get_by_role('button', name='로그아웃', exact=True).click()
                page.get_by_role('link', name='글쓰기', exact=True).click()
                expect(page).to_have_url(base + '/board/login')
                page.goto(base + '/lab')
                page.locator('#reset').click()
                page.locator('#confirm-reset').click()
                expect(page.locator('#notice')).to_contain_text('초기화')
                page.goto(base + '/board')
                expect(page.locator('tbody')).to_contain_text('아직 작성한 글이 없습니다')
                expect(page.locator('.learning-empty')).to_be_visible()
                assert not errors, errors
                assert not external, external
                browser.close()
                print('Integrated board: SQL comparison/auth/author, stored XSS on open, sandbox isolation, timeout/error, logout/reset, responsive layouts PASS')
        finally:
            server.shutdown()
            thread.join(timeout=5)


if __name__ == '__main__':
    main()
