"""Windows console-free start/stop. Runtime files stay inside instance/."""
import argparse
import ctypes
import json
import msvcrt
from pathlib import Path
import sys
import time
import traceback
import webbrowser

ROOT = Path(__file__).resolve().parent


def acquire(lock):
    lock.seek(0)
    try:
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['start', 'stop'])
    parser.add_argument('--data-dir', type=Path, default=ROOT / 'instance')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--quiet', action='store_true', help='Do not open browser or message boxes')
    args = parser.parse_args()
    folder = args.data_dir.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    # pythonw has no stdout/stderr; Werkzeug must still have a writable error stream.
    with (folder / 'launcher.log').open('a', encoding='utf-8') as log:
        sys.stdout = sys.stderr = log
        try:
            with (folder / 'launcher.lock').open('a+b') as lock:
                if lock.seek(0, 2) == 0:
                    lock.write(b'0')
                    lock.flush()
                started = time.time_ns()
                owned = acquire(lock)
                stop = folder / 'launcher.stop'
                state = folder / 'launcher.json'
                if args.action == 'stop':
                    if not owned:
                        stop.touch()
                        deadline = time.monotonic() + 15
                        while not acquire(lock):
                            if time.monotonic() >= deadline:
                                raise RuntimeError('종료를 기다리는 시간이 초과되었습니다. 잠시 후 다시 종료하세요.')
                            time.sleep(0.1)
                    lock.close()
                    if not args.quiet:
                        ctypes.windll.user32.MessageBoxW(0, 'Security Lab이 종료된 상태입니다. 저장한 글은 유지됩니다.', 'Security Lab', 0)
                    return 0
                if not owned:
                    # The first process writes its URL only after binding the socket.
                    deadline = time.monotonic() + 15
                    while not state.exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError('기존 실행이 준비되지 않았습니다. 종료 후 다시 시작하세요.')
                        time.sleep(0.1)
                    url = json.loads(state.read_text(encoding='utf-8'))['url']
                    if not args.quiet:
                        webbrowser.open(url)
                    return 0
                state.unlink(missing_ok=True)
                if stop.exists() and stop.stat().st_mtime_ns < started:
                    stop.unlink()
                from app import create_app
                from werkzeug.serving import make_server
                app = create_app(folder / 'lab.sqlite3')
                try:
                    server = make_server('127.0.0.1', args.port, app, threaded=True)
                except SystemExit as error:
                    raise RuntimeError(f'{args.port} 포트를 사용할 수 없습니다. 기존 run.bat 실행 창이나 해당 포트를 사용하는 프로그램을 종료하세요.') from error
                try:
                    server.timeout = 0.25
                    # Wait for in-flight requests before releasing the instance lock.
                    server.daemon_threads = False
                    url = f'http://127.0.0.1:{server.server_port}/board'
                    pending = state.with_suffix('.tmp')
                    pending.write_text(json.dumps({'url': url}), encoding='utf-8')
                    pending.replace(state)
                    if not args.quiet:
                        webbrowser.open(url)
                    while not stop.exists():
                        server.handle_request()
                finally:
                    server.server_close()
                    state.unlink(missing_ok=True)
                    stop.unlink(missing_ok=True)
            return 0
        except Exception as error:
            traceback.print_exc()
            log.flush()
            if not args.quiet:
                ctypes.windll.user32.MessageBoxW(0, f'실행을 완료하지 못했습니다.\n{error}\n\n기록: {folder / "launcher.log"}', 'Security Lab', 16)
            return 1


if __name__ == '__main__':
    raise SystemExit(main())
