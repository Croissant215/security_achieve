"""Windows launcher integration: hidden processes, isolated data and ports."""
import http.cookiejar
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
PYTHONW = ROOT / '.venv/Scripts/pythonw.exe'


class LauncherTests(unittest.TestCase):
    def test_start_duplicate_stop_restart_and_port_conflict(self):
        with tempfile.TemporaryDirectory(prefix='lab 한글 ') as folder:
            data = Path(folder)
            command = [str(PYTHONW), str(ROOT / 'launcher.pyw')]

            def launch(action, port=0):
                return subprocess.Popen(command + [action, '--quiet', '--data-dir', folder, '--port', str(port)],
                                        creationflags=subprocess.CREATE_NO_WINDOW)

            def ready(process):
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        self.fail((data / 'launcher.log').read_text(encoding='utf-8'))
                    if (data / 'launcher.json').exists():
                        return json.loads((data / 'launcher.json').read_text(encoding='utf-8'))['url']
                    time.sleep(0.1)
                self.fail('server readiness timeout')

            process = launch('start')
            try:
                url = ready(process)
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                                    urllib.request.ProxyHandler({}))

                def request(path, fields=None):
                    body = urllib.parse.urlencode(fields).encode() if fields is not None else None
                    with opener.open(url.removesuffix('/board') + path, body, timeout=10) as response:
                        return response.read().decode()

                page = request('/board/login')
                token = re.search(r'name="token" value="([^"]+)"', page)[1]
                request('/board/login', dict(token=token, username='student', password='study1234', mode='secure'))
                request('/board/new', dict(token=token, title='restart survives', body='saved body'))
                self.assertEqual(launch('start').wait(15), 0)
                self.assertIsNone(process.poll())
                self.assertEqual(launch('stop').wait(20), 0)
                self.assertEqual(process.wait(10), 0)
                self.assertFalse((data / 'launcher.json').exists())
                self.assertEqual(launch('stop').wait(10), 0)
                process = launch('start')
                url = ready(process)
                page = request('/board')
                self.assertIn('restart survives', page)
                self.assertIn('student 로그인 중', page)
            finally:
                launch('stop').wait(20)
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()  # Only the test-owned child, never a saved PID.
                    process.wait()
            with socket.socket() as occupied:
                occupied.bind(('127.0.0.1', 0))
                occupied.listen()
                self.assertEqual(launch('start', occupied.getsockname()[1]).wait(15), 1)
                self.assertFalse((data / 'launcher.json').exists())
                self.assertIn('포트를 사용할 수 없습니다', (data / 'launcher.log').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
