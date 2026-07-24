(() => {
  const form = document.getElementById('regForm');
  if (!form) return;

  const token = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const msg = document.getElementById('msg');
  const submit = form.querySelector('button[type="submit"]');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    msg.className = 'alert';
    msg.textContent = 'Создаём аккаунт…';
    if (submit) submit.disabled = true;

    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
      body: JSON.stringify({
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        key: document.getElementById('key').value,
      }),
    });
    const data = await res.json();

    if (submit) submit.disabled = false;
    msg.className = `alert ${res.ok ? 'success' : 'error'}`;
    msg.textContent = res.ok ? 'Аккаунт создан. Теперь можно войти.' : (data.error || 'Не удалось создать аккаунт.');
  });
})();
