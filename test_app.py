"""Backend regression checks. Run: python -m unittest -v test_app"""
import re
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
        page = self.client.get('/').get_data(as_text=True)
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
        other.get('/')
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


if __name__ == '__main__':
    unittest.main()
