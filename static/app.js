'use strict';

const $ = id => document.getElementById(id);
const modes = ['vulnerable', 'secure'];
const modeName = mode => mode === 'secure' ? '방어' : '취약';
let lesson = 'sql', mode = 'vulnerable', catalog, busy = false;
let results = {}, logs = [];

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function notice(message, error = false) {
  $('notice').textContent = message;
  $('notice').classList.toggle('error', error);
}

async function api(path, data) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(path, {
      method: data === undefined ? 'GET' : 'POST', signal: controller.signal,
      headers: {'Content-Type': 'application/json', 'X-Lab-Token': document.querySelector('meta[name="lab-token"]').content},
      ...(data === undefined ? {} : {body: JSON.stringify(data)})
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `요청 실패 (${response.status})`);
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('요청 시간이 초과되었습니다. 결과를 판정할 수 없습니다.');
    throw error;
  } finally { clearTimeout(timer); }
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll('button, input, textarea').forEach(node => node.disabled = value);
  $('workspace').setAttribute('aria-busy', String(value));
}

function inputs() {
  return lesson === 'sql' ? {username: $('username').value, password: $('password').value} : {body: $('body').value};
}

function updateComparison() {
  const fingerprint = JSON.stringify(inputs());
  const old = Object.values(results).some(result => result.input !== fingerprint);
  const both = modes.every(key => results[key]);
  const equal = both && results.vulnerable.input === results.secure.input;
  $('comparison-note').classList.toggle('changed', old || (both && !equal));
  $('comparison-note').textContent = old ? '입력이 변경되었습니다. 아래 결과는 이전 입력의 기록입니다. 같은 조건으로 비교하려면 두 모드를 다시 실행하세요.' :
    both && equal ? '같은 입력으로 실행한 취약·방어 결과입니다.' :
    both ? '입력이 서로 다릅니다. 같은 입력으로 두 모드를 다시 실행하세요.' : '취약 코드를 실행한 뒤 방어를 적용해 다시 실행하세요.';
}

function applyMode(next) {
  mode = next;
  $('mode-badge').textContent = `현재: ${modeName(mode)} 모드`;
  $('mode-badge').classList.toggle('warning', mode === 'vulnerable');
  $('run-label').textContent = mode === 'secure' ? '방어 코드 실행' : '취약 코드 실행';
  $('defend').textContent = mode === 'secure' ? '취약 모드로 전환' : '방어 적용';
  $('defend').disabled = busy;
  modes.forEach(key => $(`code-${key}-wrap`).classList.toggle('code-active', key === mode));
  $('input-state').textContent = mode === 'secure' ? '현재 입력을 방어 코드로 실행합니다.' : '예제를 불러온 뒤 입력을 수정할 수 있습니다.';
}

function addLog(log) {
  logs.push(log);
  // ponytail: retain only the latest 100 UI entries; export is outside v0.1.
  logs = logs.slice(-100);
  $('log-count').textContent = `${logs.length}건`;
  $('log-list').replaceChildren(...logs.slice().reverse().map(item => {
    const li = element('li');
    li.append(element('strong', `${item.time} · ${modeName(item.mode)} · ${item.operation}`));
    li.append(element('pre', `${item.request}\n입력: ${JSON.stringify(item.content)}\n처리: ${item.process}\n결과: ${item.result}`));
    return li;
  }));
}

function loadExample(example) {
  if (lesson === 'sql') {
    $('username').value = example.username;
    $('password').value = example.password;
  } else $('body').value = example.body;
  updateComparison();
  notice(`‘${example.name}’ 예제를 불러왔습니다. ‘${modeName(mode)} 코드 실행’을 누르세요.`);
}

function selectLesson(next) {
  lesson = next;
  results = {};
  document.querySelectorAll('[data-lesson]').forEach(button => {
    const active = button.dataset.lesson === lesson;
    button.classList.toggle('active', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const sql = lesson === 'sql';
  $('breadcrumb').textContent = sql ? '01. SQL 인젝션' : '02. 저장형 XSS';
  $('lesson-number').textContent = sql ? 'LAB 01 / SQL INJECTION' : 'LAB 02 / STORED XSS';
  $('lesson-title').textContent = sql ? 'SQL 인젝션으로 로그인 우회하기' : '게시글에 저장된 스크립트 실행하기';
  $('lesson-description').textContent = sql ? "아이디에 admin' --를 넣고 로그인해 보세요. 방어를 적용한 뒤 같은 입력으로 다시 실행해 로그인 결과를 비교합니다." : '스크립트가 들어 있는 게시글을 저장하고 다시 엽니다. 방어 적용 전에는 스크립트가 실행되고, 적용 후에는 코드가 글자로 표시되는지 확인합니다.';
  document.querySelector('.lesson-meta span').textContent = sql ? '실제 SQLite 쿼리' : '저장 후 브라우저에서 관찰';
  $('sql-inputs').hidden = !sql;
  $('xss-inputs').hidden = sql;
  $('account-hint').hidden = !sql;
  ['username', 'password'].forEach(id => $(id).required = sql);
  $('body').required = !sql;
  const cases = catalog[`${lesson}_cases`];
  $('examples').replaceChildren(...cases.map(example => {
    const button = element('button', example.name);
    button.type = 'button';
    button.addEventListener('click', () => loadExample(example));
    return button;
  }));
  modes.forEach(key => {
    $(`code-${key}`).textContent = catalog.code[lesson][key];
    $(`tag-${key}`).textContent = '실행 전';
    const empty = element('div', undefined, 'empty-result');
    empty.append(element('p', '아직 실행하지 않았습니다.'),
      element('small', key === 'secure' ? '‘방어 적용’을 누른 뒤 ‘방어 코드 실행’을 누르세요.' : '입력을 확인하고 ‘취약 코드 실행’을 누르세요.'));
    $(`output-${key}`).replaceChildren(empty);
  });
  const steps = sql ? [
    '취약 코드는 입력을 SQL 문자열에 직접 연결합니다. 따옴표와 주석이 쿼리의 의미를 바꿀 수 있습니다.',
    "admin' --를 입력하면 -- 뒤의 비밀번호 검사 조건이 주석으로 처리됩니다. 비밀번호가 틀려도 admin 계정으로 로그인됩니다.",
    '방어 코드는 SQL의 ? 자리에 입력값을 별도로 전달합니다. 이를 매개변수 바인딩이라고 합니다. 우회 입력 전체를 아이디로 조회하므로 로그인에 실패합니다.',
    'verify_password는 입력한 비밀번호를 저장된 scrypt 해시와 대조하는 SQLite 함수입니다. 정상 로그인에서는 두 모드 모두 이 함수를 실행합니다.'
  ] : [
    '두 모드 모두 SQLite에 같은 게시글 원문을 저장합니다. 차이는 다시 열 때의 출력 방식입니다.',
    '취약 코드는 저장된 HTML을 그대로 출력합니다. 브라우저가 script 태그를 읽으면 labSignal()을 실행합니다. 방어 코드는 html.escape로 <를 &lt;처럼 바꿔 태그를 글자로 표시합니다.',
    '실습 영역은 같은 격리 정책을 사용합니다. 주 화면 접근, 외부 자원 요청, 팝업과 폼 전송은 제한됩니다.',
    '‘실행 신호 없음’은 관찰 시간 동안 labSignal()이나 alert() 호출을 받지 못했다는 뜻입니다. 다른 방식으로 실행되거나 늦게 실행되는 코드는 확인하지 못할 수 있습니다. 전체 검증은 준비된 예제의 신호와 표시된 글을 함께 확인합니다.'
  ];
  const list = element('ol');
  steps.forEach(text => list.append(element('li', text)));
  $('explanation-content').replaceChildren(list);
  document.querySelector('.explanation').open = false;
  clearVerification();
  applyMode('vulnerable');
  loadExample(cases[0]);
  updateComparison();
}

function clearVerification() {
  $('verify-status').textContent = '아직 검증을 실행하지 않았습니다.';
  const td = element('td', '전체 검증을 실행하면 6개 결과가 표시됩니다.', 'table-empty');
  td.colSpan = 5;
  const tr = element('tr'); tr.append(td);
  $('verification-body').replaceChildren(tr);
  $('verification-frames').replaceChildren();
}

function observeFrame(post, container, label) {
  return new Promise((resolve, reject) => {
    const frame = element('iframe');
    frame.title = label;
    frame.setAttribute('sandbox', 'allow-scripts');
    frame.referrerPolicy = 'no-referrer';
    const cleanup = () => { clearTimeout(timer); window.removeEventListener('message', onMessage); };
    const timer = setTimeout(() => { cleanup(); frame.remove(); reject(new Error('6초 안에 게시글 실행 결과를 받지 못했습니다. 다시 실행하세요.')); }, 6000);
    function onMessage(event) {
      const data = event.data;
      if (event.source !== frame.contentWindow || !data || data.type !== 'lab-observation' || data.id !== post.id) return;
      if (typeof data.signaled !== 'boolean' || typeof data.text !== 'string' || !Array.isArray(data.errors)) return;
      cleanup();
      resolve(data);
    }
    window.addEventListener('message', onMessage);
    frame.src = post.preview_url;
    container.append(frame);
  });
}

async function runPost(currentMode, body, container) {
  const post = await api('/api/posts', {mode: currentMode, body});
  addLog(post.log);
  const reopened = await api(`/api/posts/${post.id}`);
  addLog(reopened.log);
  const observation = await observeFrame(post, container, `${modeName(currentMode)} 모드 게시글`);
  addLog({time: new Date().toISOString(), mode: currentMode, operation: '브라우저 관찰', request: `GET ${post.preview_url}`,
    content: {post: post.id}, process: '격리된 실습 영역의 실행 신호·표시 결과 수신',
    result: JSON.stringify(observation)});
  if (observation.errors.length) throw new Error(observation.errors.join(' / '));
  return {post, observation};
}

async function run() {
  if (busy) return;
  const input = inputs(), currentMode = mode;
  const output = $(`output-${currentMode}`);
  setBusy(true);
  $(`tag-${currentMode}`).textContent = '실행 중';
  output.replaceChildren(element('p', '서버 응답을 기다리는 중입니다…'));
  try {
    if (lesson === 'sql') {
      const result = await api('/api/login', {mode: currentMode, ...input});
      addLog(result.log);
      if (result.error) throw new Error(result.error);
      const title = element('h3', result.authenticated ? '로그인 성공' : '로그인 실패', `outcome ${result.authenticated ? 'success' : ''}`);
      output.replaceChildren(title, element('p', result.authenticated ? `접속한 가상 계정: ${result.user.username} · ID ${result.user.id}` : '아이디 또는 비밀번호가 일치하지 않습니다. 회원 페이지에 접근할 수 없습니다.'));
      if (result.member_url) {
        const link = element('a', '실습용 회원 페이지 열기 ↗', 'button');
        link.href = result.member_url; link.target = '_blank'; link.rel = 'noopener'; output.append(link);
      }
      results[currentMode] = {input: JSON.stringify(input), result};
    } else {
      output.replaceChildren();
      const heading = element('h3', '게시글 관찰 중', 'outcome');
      const description = element('p', '저장한 게시글을 다시 열고 있습니다.');
      const frameContainer = element('div');
      output.append(heading, description, frameContainer);
      const result = await runPost(currentMode, input.body, frameContainer);
      const observation = result.observation;
      heading.textContent = observation.signaled ? '실습 스크립트 실행됨' : '실행 신호 없음';
      heading.classList.add(observation.signaled ? 'warning' : 'success');
      description.textContent = observation.signaled ? '게시글에서 labSignal() 또는 alert()가 실행되었습니다.' : observation.text === input.body ? '입력한 내용이 글자로 표시되었습니다. 관찰 시간 동안 labSignal() 또는 alert() 호출은 없었습니다.' : '표시된 글은 아래와 같습니다. 관찰 시간 동안 실행 신호가 없었으며, 다른 코드의 실행 여부는 알 수 없습니다.';
      results[currentMode] = {input: JSON.stringify(input), result};
      const reopen = element('button', '저장한 게시글 다시 열기', 'button');
      reopen.addEventListener('click', async () => {
        setBusy(true);
        try {
          const saved = await api(`/api/posts/${result.post.id}`); addLog(saved.log);
          frameContainer.replaceChildren();
          const observed = await observeFrame(result.post, frameContainer, '저장된 게시글 재열람');
          if (observed.errors.length) throw new Error(observed.errors.join(' / '));
          notice('저장된 게시글을 다시 열었습니다.');
        } catch (error) { notice(error.message, true); }
        finally { setBusy(false); }
      });
      output.append(reopen);
    }
    $(`tag-${currentMode}`).textContent = '실행 완료';
    output.append(element('div', `${new Date().toLocaleTimeString('ko-KR')} · ${modeName(currentMode)} 모드의 실행 기록`, 'run-stamp'));
    notice(currentMode === 'vulnerable' ? '취약 코드 실행을 마쳤습니다. ‘방어 적용’을 누르고 같은 입력으로 다시 실행하세요.' : '방어 코드 실행을 마쳤습니다. ‘전체 검증 실행’으로 정상 입력과 공격 예제를 함께 확인할 수 있습니다.');
  } catch (error) {
    delete results[currentMode];
    $(`tag-${currentMode}`).textContent = '오류';
    output.replaceChildren(element('h3', '판정할 수 없습니다', 'outcome error'), element('p', error.message));
    notice(error.message, true);
  } finally { updateComparison(); setBusy(false); }
}

function verificationRow(test, currentMode, expected) {
  const tr = element('tr');
  const observed = element('td', '—'), status = element('td', '미실행');
  tr.append(element('td', `${test.id} · ${test.name}`), element('td', modeName(currentMode)), element('td', expected), observed, status);
  $('verification-body').append(tr);
  return {observed, status};
}

function setStatus(row, observed, status) {
  row.observed.textContent = observed;
  row.status.textContent = status;
  row.status.className = status === '통과' ? 'state-pass' : status === '실패' ? 'state-fail' : status === '오류' ? 'state-error' : '';
}

async function verify() {
  if (busy) return;
  setBusy(true);
  $('verify').textContent = '검증 중…';
  $('verification-body').replaceChildren();
  $('verification-frames').replaceChildren();
  $('verify-status').textContent = '예제 3개를 취약·방어 모드에서 각각 실행하고 있습니다.';
  let passed = 0;
  try {
    if (lesson === 'sql') {
      const rows = catalog.sql_cases.flatMap(test => modes.map((key, index) => verificationRow(test, key, test.expected[index] ? '로그인 성공' : '로그인 실패')));
      rows.forEach(row => row.status.textContent = '실행 중');
      try {
        const data = await api('/api/verify/sql', {});
        data.results.forEach((result, index) => {
          const value = result.observed;
          setStatus(rows[index], value.error || (value.authenticated ? `로그인 성공 · ${value.user.username}` : '로그인 실패'), result.status);
          addLog(result.log);
          if (result.status === '통과') passed++;
        });
      } catch (error) { rows.forEach(row => setStatus(row, error.message, '오류')); throw error; }
    } else {
      let positiveControl = false;
      const entries = catalog.xss_cases.flatMap(test => modes.map(key => ({test, key,
        row: verificationRow(test, key, test.id === 'XSS-01' ? '입력한 글 정상 표시' : test.id === 'XSS-02' ? (key === 'secure' ? '입력 문자열 그대로' : '굵은 안녕 + &') : (key === 'secure' ? '코드가 글자로 표시 · 신호 없음' : '실제 스크립트 신호'))})));
      for (const {test, key, row} of entries) {
        row.status.textContent = '실행 중';
        const detail = element('details');
        detail.append(element('summary', `${test.id} · ${modeName(key)} 게시글 보기`));
        const frameContainer = element('div'); detail.append(frameContainer);
        $('verification-frames').append(detail);
        try {
          const {observation: observed} = await runPost(key, test.body, frameContainer);
          let match;
          if (test.id === 'XSS-01') match = observed.text === test.body && !observed.signaled;
          else if (test.id === 'XSS-02') match = !observed.signaled && (key === 'secure' ? observed.text === test.body && !observed.bold : observed.text === '안녕 &' && observed.bold);
          else if (key === 'vulnerable') { match = observed.signaled; positiveControl = match; }
          else {
            if (!positiveControl) throw new Error('취약 모드의 실행 신호를 확인하지 못해 방어 효과를 판정할 수 없습니다.');
            match = !observed.signaled && observed.text === test.body;
          }
          setStatus(row, observed.signaled ? '스크립트 실행 신호 확인' : `${observed.bold ? '굵게 표시 · ' : ''}${observed.text} · 신호 없음`, match ? '통과' : '실패');
          if (match) passed++;
        } catch (error) { setStatus(row, error.message, '오류'); }
      }
    }
    $('verify-status').textContent = `검증 완료 · ${passed}/6 통과${passed < 6 ? ' · 실패 또는 오류 항목을 확인하세요.' : ''}`;
    notice(`전체 검증을 완료했습니다. ${passed}/6개가 기대 결과와 일치합니다.`, passed < 6);
  } catch (error) { $('verify-status').textContent = '검증 오류 · 결과를 판정하지 않았습니다.'; notice(error.message, true); }
  finally { $('verify').textContent = '전체 검증 실행'; setBusy(false); }
}

document.querySelectorAll('[data-lesson]').forEach(button => button.addEventListener('click', () => selectLesson(button.dataset.lesson)));
$('lab-form').addEventListener('submit', event => { event.preventDefault(); run(); });
['username', 'password', 'body'].forEach(id => $(id).addEventListener('input', updateComparison));
$('defend').addEventListener('click', () => { applyMode(mode === 'secure' ? 'vulnerable' : 'secure'); notice(`${modeName(mode)} 모드로 바꿨습니다. 입력은 그대로입니다. ‘${modeName(mode)} 코드 실행’을 누르세요.`); });
$('verify').addEventListener('click', verify);
$('reset').addEventListener('click', () => $('reset-dialog').showModal());
$('cancel-reset').addEventListener('click', () => $('reset-dialog').close());
$('confirm-reset').addEventListener('click', async () => {
  setBusy(true);
  try {
    const data = await api('/api/reset', {});
    logs = []; $('log-count').textContent = '0건';
    $('log-list').replaceChildren(element('li', '아직 실행한 요청이 없습니다.', 'muted'));
    selectLesson(lesson);
    notice(data.message);
    $('reset-dialog').close();
  } catch (error) { notice(error.message, true); $('reset-dialog').close(); }
  finally { setBusy(false); }
});

(async () => {
  setBusy(true);
  try { catalog = await api('/api/lessons'); selectLesson('sql'); }
  catch (error) { notice(`실습 자료를 불러오지 못했습니다. 서버를 확인하고 새로고침하세요. ${error.message}`, true); return; }
  finally { if (catalog) setBusy(false); }
})();
