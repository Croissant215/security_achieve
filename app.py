"""Local, fictional-data-only SQL injection and stored XSS classroom lab."""
from contextlib import closing
from datetime import datetime
import html
import inspect
import json
from pathlib import Path
import secrets
import sqlite3

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import BadSignature, URLSafeTimedSerializer

MODES = ('vulnerable', 'secure')
XSS_SAMPLE = '<script>labSignal()</script>'
SQL_CASES = [
    {'id': 'SQL-01', 'name': '정상 계정', 'username': 'student', 'password': 'study1234', 'expected': [True, True]},
    {'id': 'SQL-02', 'name': '잘못된 비밀번호', 'username': 'student', 'password': 'wrong', 'expected': [False, False]},
    {'id': 'SQL-03', 'name': '로그인 우회', 'username': "admin' --", 'password': 'wrong', 'expected': [True, False]},
]
XSS_CASES = [
    {'id': 'XSS-01', 'name': '일반 게시글', 'body': '안녕하세요'},
    {'id': 'XSS-02', 'name': 'HTML과 일반 텍스트', 'body': '<b>안녕</b> &amp;'},
    {'id': 'XSS-03', 'name': '실습용 스크립트', 'body': XSS_SAMPLE},
]


def vulnerable_login(db, username, password):
    # Intentionally vulnerable, only on a new in-memory fictional account DB.
    query = f"SELECT id, username FROM users WHERE username = '{username}' AND verify_password(password_hash, '{password}') = 1"
    return db.execute(query).fetchone(), query


def secure_login(db, username, password):
    query = 'SELECT id, username FROM users WHERE username = ? AND verify_password(password_hash, ?) = 1'
    return db.execute(query, (username, password)).fetchone(), query


def vulnerable_render(body):
    return body  # Intentional HTML interpretation inside the sandbox only.


def secure_render(body):
    return html.escape(body)  # Encode for an HTML text context on output.


def save_board_post(db, post_id, owner, mode, title, body, author, created_at):
    db.execute('INSERT INTO posts (id, owner, mode, title, body, author, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
               (post_id, owner, mode, title, body, author, created_at))
    db.commit()


def load_board_post(db, post_id, owner):
    return db.execute("SELECT * FROM posts WHERE id = ? AND owner = ? AND title != ''",
                      (post_id, owner)).fetchone()


def create_app(database=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=24_000,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
        TRUSTED_HOSTS=['localhost', '127.0.0.1'],
    )
    db_path = Path(database) if database else Path(app.instance_path) / 'lab.sqlite3'
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS posts (id TEXT PRIMARY KEY, owner TEXT NOT NULL, mode TEXT NOT NULL, body TEXT NOT NULL)')
        columns = {row[1] for row in db.execute('PRAGMA table_info(posts)')}
        for column in ('title', 'author', 'created_at'):
            if column not in columns:
                db.execute(f"ALTER TABLE posts ADD COLUMN {column} TEXT NOT NULL DEFAULT ''")
        db.execute('CREATE TABLE IF NOT EXISTS board_trace (owner TEXT PRIMARY KEY, event TEXT NOT NULL)')
        db.commit()
    preview_signer = URLSafeTimedSerializer(app.secret_key, salt='board-preview')
    accounts = [(1, 'admin', generate_password_hash('admin1234')), (2, 'student', generate_password_hash('study1234'))]

    def authenticate(mode, username, password):
        # Each execution starts from identical data; attacks cannot alter the post DB.
        with closing(sqlite3.connect(':memory:')) as db:
            db.row_factory = sqlite3.Row
            db.execute('CREATE TABLE users (id INTEGER, username TEXT, password_hash TEXT)')
            db.executemany('INSERT INTO users VALUES (?, ?, ?)', accounts)
            checks = 0

            def verify_password(hashed, value):
                nonlocal checks
                checks += 1
                if checks > 8:
                    raise ValueError('Password check limit exceeded')
                if hashed not in (account[2] for account in accounts):
                    return 0
                return int(check_password_hash(hashed, value))

            db.create_function('verify_password', 2, verify_password)
            db.execute('PRAGMA query_only = ON')
            # Disallow custom allocation/file functions while retaining SQLi predicates.
            db.set_authorizer(lambda action, arg1, arg2, *_:
                sqlite3.SQLITE_OK if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ)
                or (action == sqlite3.SQLITE_FUNCTION and arg2 == 'verify_password')
                else sqlite3.SQLITE_DENY)
            # Bound work even for custom expensive SQL input.
            db.set_progress_handler(lambda: 1, 50_000)
            function = secure_login if mode == 'secure' else vulnerable_login
            try:
                row, query = function(db, username, password)
            except sqlite3.Error as error:
                return {'error': f'SQL 실행 오류: {error}', 'authenticated': None}
            user = dict(row) if row else None
            # A forged UNION result is not a real member account.
            if user and not any(user['id'] == a[0] and user['username'] == a[1] for a in accounts):
                return {'error': '가상 계정과 일치하지 않는 쿼리 결과입니다.', 'authenticated': None, 'query': query}
            return {'authenticated': bool(user), 'user': user, 'query': query}

    def record(mode, operation, content, process, result):
        return {'time': datetime.now().astimezone().isoformat(timespec='milliseconds'),
                'mode': mode, 'request': f'{request.method} {request.path}',
                'operation': operation, 'content': content, 'process': process, 'result': result}

    @app.before_request
    def protect_lab():
        if request.endpoint in ('index', 'board', 'board_new', 'board_detail', 'board_login', 'board_logout'):
            session.setdefault('owner', secrets.token_hex(16))
            session.setdefault('lab_token', secrets.token_hex(24))
        if request.path.startswith('/board') and request.method == 'POST':
            if not session.get('lab_token') or not secrets.compare_digest(request.form.get('token', '').encode(), session['lab_token'].encode()):
                abort(403, '글쓰기 페이지를 다시 열어 작성하세요.')
        if request.path.startswith('/api/') and request.method == 'POST':
            token = session.get('lab_token', '')
            if not token or not secrets.compare_digest(request.headers.get('X-Lab-Token', '').encode(), token.encode()):
                abort(403, '실습 페이지를 새로고침한 후 다시 실행하세요.')
            if not request.is_json:
                abort(415, 'JSON 형식의 요청이 필요합니다.')

    @app.after_request
    def headers(response):
        preview = request.path.startswith('/preview/')
        response.headers['Content-Security-Policy'] = (
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-scripts"
            if preview else
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
            "connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        if request.path.startswith('/api/'):
            return jsonify(error=error.description), error.code
        return render_template('message.html', title=f'{error.code} · 요청을 처리할 수 없습니다', message=error.description), error.code

    @app.errorhandler(sqlite3.Error)
    def storage_error(error):
        app.logger.error('Lab database failure: %s', error)
        message = '실습 데이터 저장소를 사용할 수 없습니다. 다른 실행 창을 닫고 다시 시도하세요.'
        if request.path.startswith('/api/'):
            return jsonify(error=message), 503
        return render_template('message.html', title='저장소 오류', message=message), 503

    def data_for_mode():
        data = request.get_json()
        if not isinstance(data, dict) or data.get('mode') not in MODES:
            abort(400, '실행 모드를 확인하세요.')
        return data

    def text_field(data, key, maximum):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            abort(400, f'{key}: 1~{maximum}자의 내용을 입력하세요.')
        return value

    @app.get('/')
    def home():
        return redirect(url_for('board'))

    @app.get('/lab')
    def index():
        return render_template('index.html', token=session['lab_token'])

    def board_event(operation, inputs, results):
        event = dict(operation=operation, request=f'{request.method} {request.path}',
                     time=datetime.now().astimezone().isoformat(timespec='seconds'), inputs=inputs, results=results)
        with closing(sqlite3.connect(db_path)) as db:
            db.execute('INSERT INTO board_trace (owner, event) VALUES (?, ?) ON CONFLICT(owner) DO UPDATE SET event = excluded.event',
                       (session['owner'], json.dumps(event, ensure_ascii=False)))
            db.commit()

    def board_page(view, **context):
        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute('SELECT event FROM board_trace WHERE owner = ?', (session['owner'],)).fetchone()
        return render_template('board.html', view=view, trace=json.loads(row[0]) if row else None,
                               user=session.get('board_user'), mode=session.get('board_mode', 'secure'),
                               **context)

    @app.route('/board/login', methods=['GET', 'POST'])
    def board_login():
        username, password, error = '', '', None
        if request.method == 'POST':
            selected = request.form.get('mode')
            if selected not in MODES:
                abort(400, '로그인 처리 모드를 확인하세요.')
            session['board_mode'] = selected
            session.pop('board_user', None)
            username, password = request.form.get('username', ''), request.form.get('password', '')
            if not username.strip() or not password.strip() or max(len(username), len(password)) > 200:
                return board_page('login', username=username, password='', error='아이디와 비밀번호를 각각 1~200자로 입력하세요.'), 400
            modes = MODES if request.form.get('compare') == 'yes' else (selected,)
            results = []
            for execution_mode in modes:
                result = authenticate(execution_mode, username, password)
                label = result.get('error') or (f"로그인 성공 · {result['user']['username']}" if result['authenticated'] else '로그인 실패 · 계정 정보를 확인하세요.')
                results.append(dict(mode=execution_mode, result=label, query=result.get('query', ''),
                                    code=inspect.getsource(secure_login if execution_mode == 'secure' else vulnerable_login)))
                if execution_mode == selected:
                    if result.get('user'):
                        session['board_user'] = result['user']
                    else:
                        error = label
            board_event('로그인', {'아이디': username, '비밀번호': '가상 실습 입력 · SQL에 표시될 수 있음'}, results)
            if session.get('board_user'):
                flash('로그인했습니다. 글을 작성하거나 목록에서 게시글을 열어 보세요.')
                return redirect(url_for('board'), code=303)
        return board_page('login', username=username, password=password, error=error)

    @app.post('/board/logout')
    def board_logout():
        session.pop('board_user', None)
        board_event('로그아웃', {}, [dict(result='게시판 로그인 상태를 삭제했습니다.', code="session.pop('board_user', None)")])
        return redirect(url_for('board'), code=303)

    @app.get('/board')
    def board():
        with closing(sqlite3.connect(db_path)) as db:
            db.row_factory = sqlite3.Row
            posts = db.execute("SELECT id, title, author, created_at FROM posts WHERE owner = ? AND title != '' ORDER BY created_at DESC, rowid DESC",
                               (session['owner'],)).fetchall()
        return board_page('list', posts=posts)

    @app.route('/board/new', methods=['GET', 'POST'])
    def board_new():
        if not session.get('board_user'):
            if request.method == 'POST':
                abort(403, '글을 저장하려면 게시판에서 먼저 로그인하세요.')
            return redirect(url_for('board_login'))
        title, body, error = '', '', None
        status = 200
        if request.method == 'POST':
            title, body = request.form.get('title', ''), request.form.get('body', '')
            if not title.strip() or len(title) > 100 or not body.strip() or len(body) > 4000:
                error, status = '제목은 1~100자, 본문은 1~4,000자로 입력하세요. 공백만 입력할 수 없습니다.', 400
            else:
                try:
                    with closing(sqlite3.connect(db_path)) as db:
                        save_board_post(db, secrets.token_hex(24), session['owner'], session.get('board_mode', 'secure'),
                                        title.strip(), body, session['board_user']['username'],
                                        datetime.now().astimezone().isoformat(timespec='seconds'))
                except sqlite3.Error:
                    app.logger.exception('Board post could not be saved')
                    error, status = '글을 저장하지 못했습니다. 입력한 내용을 확인하고 다시 저장하세요.', 503
                else:
                    board_event('글 저장', {'제목': title.strip(), '본문': body},
                                [dict(result='SQLite 저장 완료 · 본문은 아직 브라우저에서 열지 않았습니다.', code=inspect.getsource(save_board_post))])
                    flash('글을 저장했습니다. 제목을 누르면 본문을 볼 수 있습니다.')
                    return redirect(url_for('board'), code=303)
        return board_page('new', title=title, body=body, error=error), status

    @app.get('/board/<post_id>')
    def board_detail(post_id):
        with closing(sqlite3.connect(db_path)) as db:
            db.row_factory = sqlite3.Row
            post = load_board_post(db, post_id, session['owner'])
        if post is None:
            abort(404, '게시글이 없거나 초기화되었습니다. 게시판 목록에서 다시 확인하세요.')
        output_mode = request.args.get('mode', session.get('board_mode', 'secure'))
        if output_mode not in MODES:
            abort(400, '본문 출력 모드를 확인하세요.')
        board_event('게시글 열람', {'게시글 ID': post_id},
                    [dict(result='SQLite 원문 조회 완료', code=inspect.getsource(load_board_post))])
        output_modes = [output_mode]
        if request.args.get('compare') == 'yes':
            output_modes += [mode for mode in MODES if mode != output_mode]
        previews = [dict(mode=mode, url=url_for('board_preview', ticket=preview_signer.dumps(
            dict(id=post_id, owner=session['owner'], mode=mode))),
            code=inspect.getsource(secure_render if mode == 'secure' else vulnerable_render)) for mode in output_modes]
        return board_page('detail', post=post, previews=previews, output_mode=output_mode)

    @app.get('/preview/board/<ticket>')
    def board_preview(ticket):
        try:
            data = preview_signer.loads(ticket, max_age=600)
        except BadSignature:
            abort(404, '본문 요청이 만료되었거나 유효하지 않습니다. 게시글을 다시 여세요.')
        with closing(sqlite3.connect(db_path)) as db:
            db.row_factory = sqlite3.Row
            post = load_board_post(db, data['id'], data['owner'])
        if post is None:
            abort(404, '초기화된 게시글입니다.')
        rendered = secure_render(post['body']) if data['mode'] == 'secure' else vulnerable_render(post['body'])
        return render_template('preview.html', rendered=rendered, post_id=data['id'])

    @app.get('/api/lessons')
    def lessons():
        return jsonify(sql_cases=SQL_CASES, xss_cases=XSS_CASES, code={
            'sql': {mode: inspect.getsource(fn) for mode, fn in zip(MODES, [vulnerable_login, secure_login])},
            'xss': {mode: inspect.getsource(fn) for mode, fn in zip(MODES, [vulnerable_render, secure_render])},
        })

    @app.post('/api/login')
    def login():
        data = data_for_mode()
        mode = data['mode']
        username = text_field(data, 'username', 200)
        password = text_field(data, 'password', 200)
        session.pop(f'user_{mode}', None)
        result = authenticate(mode, username, password)
        if result.get('user'):
            session[f'user_{mode}'] = result['user']
            result['member_url'] = f'/member/{mode}'
        result['log'] = record(mode, '로그인', {'username': username, 'password': '실습 비밀번호 숨김'},
                               result.get('query', 'SQL 실행 중 오류'),
                               result.get('error') or ('로그인 성공' if result['authenticated'] else '로그인 실패'))
        return jsonify(result)

    @app.get('/member/<mode>')
    def member(mode):
        if mode not in MODES or not session.get(f'user_{mode}'):
            abort(403, '로그인된 가상 계정이 없습니다. 실습 화면에서 먼저 로그인하세요.')
        return render_template('member.html', user=session[f'user_{mode}'], mode=mode)

    @app.post('/api/posts')
    def post():
        data = data_for_mode()
        body = text_field(data, 'body', 4000)
        post_id = secrets.token_hex(24)
        with closing(sqlite3.connect(db_path)) as db:
            db.execute('INSERT INTO posts (id, owner, mode, body) VALUES (?, ?, ?, ?)', (post_id, session['owner'], data['mode'], body))
            db.commit()
        return jsonify(id=post_id, preview_url=f'/preview/{post_id}', log=record(
            data['mode'], '게시글 저장', {'body': body}, 'SQLite에 바인딩 쿼리로 원문 저장', f'게시글 {post_id[:8]} 저장 완료'))

    @app.get('/api/posts/<post_id>')
    def read_post(post_id):
        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute('SELECT mode, body FROM posts WHERE id = ? AND owner = ?', (post_id, session.get('owner'))).fetchone()
        if not row:
            abort(404, '게시글이 없거나 초기화되었습니다.')
        return jsonify(body=row[1], log=record(row[0], '게시글 열람', {'id': post_id},
            '저장된 원문 조회 → ' + ('html.escape 적용' if row[0] == 'secure' else '원문 HTML 출력'), '분리된 실습 영역에서 브라우저 관찰 대기'))

    @app.get('/preview/<post_id>')
    def preview(post_id):
        # Unguessable per-post capability; the sandbox does not need same-origin access.
        with closing(sqlite3.connect(db_path)) as db:
            row = db.execute('SELECT mode, body FROM posts WHERE id = ?', (post_id,)).fetchone()
        if not row:
            abort(404, '초기화된 게시글입니다.')
        rendered = secure_render(row[1]) if row[0] == 'secure' else vulnerable_render(row[1])
        return render_template('preview.html', rendered=rendered, post_id=post_id)

    @app.post('/api/verify/sql')
    def verify_sql():
        results = []
        for case in SQL_CASES:
            for index, mode in enumerate(MODES):
                result = authenticate(mode, case['username'], case['password'])
                expected = case['expected'][index]
                status = '오류' if result.get('error') else ('통과' if result['authenticated'] == expected else '실패')
                results.append({'id': case['id'], 'name': case['name'], 'mode': mode, 'expected': expected,
                    'observed': result, 'status': status, 'log': record(mode, case['id'], {'username': case['username']},
                    result.get('query', 'SQL 오류'), result.get('error') or str(result['authenticated']))})
        return jsonify(results=results)

    @app.post('/api/reset')
    def reset():
        with closing(sqlite3.connect(db_path)) as db:
            db.execute('DELETE FROM posts WHERE owner = ?', (session.get('owner'),))
            db.execute('DELETE FROM board_trace WHERE owner = ?', (session.get('owner'),))
            db.commit()
        for mode in MODES:
            session.pop(f'user_{mode}', None)
        session.pop('board_user', None)
        session.pop('board_mode', None)
        return jsonify(message='이 브라우저의 게시글과 로그인 상태를 초기화했습니다.')

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=5000, debug=False)
