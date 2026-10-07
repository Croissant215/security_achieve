"""Backend regression checks. Run: python -m unittest -v test_app"""
import re
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from app import create_app, XSS_SAMPLE


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = create_app(Path(cls.temp.name) / 'test.sqlite3')
        cls.app.testing = True

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        page = self.client.get('/lab').get_data(as_text=True)
        self.token = re.search(r'name="lab-token" content="([^"]+)"', page)[1]

    def post(self, path, data):
        return self.client.post(path, json=data, headers={'X-Lab-Token': self.token})

    def test_sql_cases_and_member_access(self):
        cases = self.client.get('/api/lessons').json['sql_cases']
        for case in cases:
            for index, mode in enumerate(('vulnerable', 'secure')):
                with self.subTest(case=case['id'], mode=mode):
                    response = self.post('/api/login', dict(mode=mode, username=case['username'], password=case['password']))
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json['authenticated'], case['expected'][index])
                    self.assertEqual(self.client.get(f'/member/{mode}').status_code, 200 if case['expected'][index] else 403)
        result = self.post('/api/verify/sql', {}).json['results']
        self.assertEqual(len(result), 6)
        self.assertTrue(all(row['status'] == '통과' for row in result))

    def test_sql_error_is_not_failed_login(self):
        self.post('/api/login', dict(mode='vulnerable', username='student', password='study1234'))
        result = self.post('/api/login', dict(mode='vulnerable', username="'", password='wrong')).json
        self.assertIsNone(result['authenticated'])
        self.assertIn('error', result)
        self.assertEqual(self.client.get('/member/vulnerable').status_code, 403)
        result = self.post('/api/login', dict(mode='vulnerable', username="' OR randomblob(999999999) --", password='wrong')).json
        self.assertIsNone(result['authenticated'])
        self.assertIn('error', result)

    def test_stored_xss_output_and_isolation_headers(self):
        for mode in ('vulnerable', 'secure'):
            with self.subTest(mode=mode):
                post = self.post('/api/posts', dict(mode=mode, body=XSS_SAMPLE)).json
                saved = self.client.get(f"/api/posts/{post['id']}")
                self.assertEqual(saved.json['body'], XSS_SAMPLE)
                preview = self.client.get(post['preview_url'])
                content = preview.get_data(as_text=True)
                expected = XSS_SAMPLE if mode == 'vulnerable' else '&lt;script&gt;labSignal()&lt;/script&gt;'
                self.assertIn(f'<article id="post-body">{expected}</article>', content)
                self.assertIn('sandbox allow-scripts', preview.headers['Content-Security-Policy'])
                self.assertNotIn('allow-same-origin', preview.headers['Content-Security-Policy'])

    def test_reset_is_scoped_and_invalidates_member(self):
        other = self.app.test_client()
        other.get('/lab')
        with other.session_transaction() as state:
            token = state['lab_token']
        unrelated = other.post('/api/posts', json=dict(mode='secure', body='다른 브라우저'), headers={'X-Lab-Token': token}).json
        own = self.post('/api/posts', dict(mode='secure', body='내 글')).json
        self.post('/api/login', dict(mode='secure', username='student', password='study1234'))
        self.assertEqual(self.client.get(f"/api/posts/{unrelated['id']}").status_code, 404)
        self.assertEqual(self.post('/api/reset', {}).status_code, 200)
        self.assertEqual(self.client.get(own['preview_url']).status_code, 404)
        self.assertEqual(self.client.get('/member/secure').status_code, 403)
        self.assertEqual(other.get(f"/api/posts/{unrelated['id']}").status_code, 200)

    def test_invalid_requests(self):
        self.assertEqual(self.client.post('/api/reset', json={}).status_code, 403)
        self.assertEqual(self.post('/api/login', []).status_code, 400)
        self.assertEqual(self.post('/api/login', dict(mode='unknown')).status_code, 400)
        self.assertEqual(self.post('/api/posts', dict(mode='secure', body='')).status_code, 400)
        self.assertEqual(self.post('/api/posts', dict(mode='secure', body='a' * 4001)).status_code, 400)
        self.assertEqual(self.client.get('/', headers={'Host': 'evil.example'}).status_code, 400)

    def test_board_flow_validation_and_isolation(self):
        direct = self.app.test_client()
        self.assertEqual(direct.get('/board/new').status_code, 302)
        with direct.session_transaction() as state:
            token = state['lab_token']
        direct.post('/board/login', data=dict(token=token, username='student', password='study1234', mode='secure'))
        fields = dict(token=token, title='<b>제목</b>', body='<script>alert(1)</script>\n다음 줄')
        for bad in ('', '잘못된 토큰'):
            self.assertEqual(direct.post('/board/new', data={**fields, 'token': bad}).status_code, 403)
        for key, value in (('title', ' '), ('title', 'a' * 101), ('body', ''), ('body', 'a' * 4001)):
            response = direct.post('/board/new', data={**fields, key: value})
            self.assertEqual(response.status_code, 400)
            self.assertIn('role="alert"', response.text)
        response = direct.post('/board/new', data=fields)
        self.assertEqual(response.status_code, 303)
        page = direct.get(response.location).text
        self.assertIn('&lt;b&gt;제목&lt;/b&gt;', page)
        detail_url = re.search(r'class="board-title" href="([^"]+)"', page)[1]
        detail = direct.get(detail_url).text
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;\n다음 줄', detail)
        self.assertNotIn('<script>alert(1)</script>', detail)
        self.assertIn('작성자 student', detail)
        self.assertEqual(direct.get('/board').text.count('class="board-title"'), 1)
        self.assertEqual(self.client.get(detail_url).status_code, 404)
        self.assertIn('load_board_post', detail)
        ticket_url = re.search(r'data-preview-url="([^"]+)"', detail)[1]
        preview = direct.get(ticket_url)
        self.assertIn('sandbox allow-scripts', preview.headers['Content-Security-Policy'])
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', preview.text)
        self.assertEqual(direct.get(ticket_url + 'tampered').status_code, 404)
        direct.post('/api/reset', json={}, headers={'X-Lab-Token': token})
        self.assertEqual(direct.get(detail_url).status_code, 404)
        self.assertEqual(direct.get(ticket_url).status_code, 404)
        self.assertIn('로그인하거나 글을 저장·열람하면', direct.get('/board').text)
        self.assertEqual(direct.get('/board/new').status_code, 302)

    def test_board_login_comparison_and_author(self):
        fields = dict(token=self.token, username="admin' --", password='wrong', compare='yes', mode='secure')
        self.assertEqual(self.client.post('/board/new', data=dict(token=self.token, title='t', body='b')).status_code, 403)
        self.assertEqual(self.client.post('/board/login', data={**fields, 'token': 'wrong'}).status_code, 403)
        result = self.client.post('/board/login', data=fields)
        self.assertIn('로그인 성공 · admin', result.text)
        self.assertIn('로그인 실패', result.text)
        self.assertEqual(self.client.get('/board/new').status_code, 302)
        result = self.client.post('/board/login', data={**fields, 'mode': 'vulnerable'}, follow_redirects=True)
        self.assertIn('admin 로그인 중', result.text)
        self.assertIn('vulnerable_login', result.text)
        self.assertIn('secure_login', result.text)
        self.client.post('/board/new', data=dict(token=self.token, title='admin의 글', body=XSS_SAMPLE, author='forged'))
        listing = self.client.get('/board').text
        detail_url = re.search(r'class="board-title" href="([^"]+)"', listing)[1]
        detail = self.client.get(detail_url + '?compare=yes').text
        self.assertIn('작성자 admin', detail)
        urls = re.findall(r'data-preview-url="([^"]+)"', detail)
        self.assertEqual(len(urls), 2)
        self.assertIn(XSS_SAMPLE, self.client.get(urls[0]).text)
        self.assertIn('&lt;script&gt;labSignal()', self.client.get(urls[1]).text)
        self.assertEqual(self.client.get(detail_url + '?mode=invalid').status_code, 400)
        self.client.post('/board/logout', data=dict(token=self.token))
        self.assertEqual(self.client.get('/board/new').status_code, 302)
        self.client.post('/board/login', data={**fields, 'username': "'", 'compare': 'no', 'mode': 'vulnerable'})
        self.assertIn('SQL 실행 오류', self.client.get('/board').text)
        self.assertEqual(self.client.get('/board/new').status_code, 302)

    def test_existing_database_migration(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'old.sqlite3'
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE posts (id TEXT PRIMARY KEY, owner TEXT NOT NULL, mode TEXT NOT NULL, body TEXT NOT NULL)')
                db.execute("INSERT INTO posts VALUES ('old', 'owner', 'secure', 'existing body')")
                db.commit()
            migrated = create_app(path)
            create_app(path)  # Repeated startup must preserve the same schema/data.
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT body, title FROM posts').fetchone(), ('existing body', ''))
            self.assertEqual(migrated.test_client().get('/board').status_code, 200)


if __name__ == '__main__':
    unittest.main()
