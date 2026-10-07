'use strict';

document.querySelectorAll('[data-example]').forEach(button => {
  button.addEventListener('click', () => {
    const form = button.closest('form');
    const sample = button.dataset.example;
    let message;
    if (sample.endsWith('login')) {
      const attack = sample === 'attack-login';
      form.elements.username.value = attack ? "admin' --" : 'student';
      form.elements.password.value = sample === 'normal-login' ? 'study1234' : 'wrong';
      form.elements.mode.value = attack ? 'vulnerable' : 'secure';
      message = attack ? '우회 예제를 입력하고 취약 코드를 선택했습니다. 아래 ‘같은 입력으로 두 모드 비교’를 눌러 결과를 확인하세요.' : '예제를 입력하고 방어 코드를 선택했습니다. 아래 ‘로그인’을 눌러 결과를 확인하세요.';
    } else {
      const xss = sample === 'xss-post';
      form.elements.title.value = xss ? '글을 열 때 실행되는 XSS 예제' : '처음 작성한 게시글';
      form.elements.body.value = xss ? '<script>labSignal()</script>' : '안녕하세요. 게시판에 글을 저장하고 다시 열어 봅니다.';
      message = '예제를 입력했습니다. 아래 ‘글 저장’을 누른 뒤 목록에서 글을 여세요.';
    }
    form.querySelector('.sample-feedback').textContent = message;
  });
});

document.querySelectorAll('.result-jump').forEach(link => {
  link.addEventListener('click', () => {
    const panel = document.querySelector('#learning-panel');
    panel.querySelector('details').open = true;
    panel.focus({preventScroll: true});
  });
});

document.querySelectorAll('form').forEach(form => {
  form.addEventListener('submit', () => {
    // Keep the clicked button's name/value in the native form submission.
    setTimeout(() => form.querySelectorAll('button[type="submit"]').forEach(button => {
      button.disabled = true;
      button.dataset.label = button.textContent;
      button.textContent = '처리 중…';
    }), 0);
  });
});
window.addEventListener('pageshow', () => {
  document.querySelectorAll('button[data-label]').forEach(button => {
    button.disabled = false;
    button.textContent = button.dataset.label;
  });
});

document.querySelectorAll('.board-preview').forEach(section => {
  const frame = section.querySelector('iframe');
  const status = section.querySelector('.observation');
  const output = document.querySelector(`[data-output-mode="${section.dataset.mode}"]`);
  let finished = false;
  const show = message => {
    status.textContent = message;
    output.querySelector('.output-state').textContent = message;
  };
  const timer = setTimeout(() => {
    finished = true;
    show('관찰 시간 초과 · 본문 요청 실패 또는 실행 지연으로 판정할 수 없습니다.');
    window.removeEventListener('message', observe);
  }, 6000);
  function observe(event) {
    if (finished || event.source !== frame.contentWindow || event.data?.type !== 'lab-observation' || event.data.id !== frame.dataset.postId) return;
    const data = event.data;
    if (!Array.isArray(data.errors) || typeof data.signaled !== 'boolean' || typeof data.text !== 'string') return;
    finished = true;
    clearTimeout(timer);
    window.removeEventListener('message', observe);
    output.querySelector('pre').classList.add('executed-code');
    if (data.errors.length) show('실행 오류 또는 격리 정책 제한 · 판정할 수 없습니다.');
    else if (data.signaled) show('실습 스크립트 실행됨 · 저장한 글을 열 때 실행 신호를 관찰했습니다.');
    else show('실행 신호 없음 · 이 관찰만으로 안전함을 판정하지 않습니다.');
  }
  window.addEventListener('message', observe);
  show('저장된 본문 요청 중 · 출력 함수와 브라우저 실행 결과를 기다립니다.');
  frame.src = frame.dataset.previewUrl;
});
