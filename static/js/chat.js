(() => {
  const token = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const container = document.getElementById('chat-container');
  const toggle = document.querySelector('.chat-header');
  const icon = document.querySelector('.toggle-icon');
  const box = document.getElementById('chat-messages');
  const input = document.getElementById('message-input');
  const send = document.getElementById('send-btn');
  if (!container || !toggle || !box || !input || !send) return;
  let visible = true;
  const appendMessage = (message) => {
    const row = document.createElement('div'); row.className = 'msg';
    const avatar = document.createElement('img'); avatar.src = `/static/${message.avatar}`; avatar.alt = '';
    const content = document.createElement('div'); content.className = 'msg-content';
    const name = document.createElement('span'); name.className = 'name'; name.textContent = message.display_name;
    const time = document.createElement('span'); time.className = 'time'; time.textContent = message.created_at;
    const text = document.createElement('div'); text.className = 'text'; text.textContent = message.message;
    content.append(name, time, text); row.append(avatar, content); box.append(row);
  };
  const loadMessages = async () => {
    if (!visible) return;
    const res = await fetch('/api/chat/messages', {headers: {'Accept': 'application/json'}});
    if (!res.ok) return;
    const messages = await res.json(); box.replaceChildren(); messages.forEach(appendMessage); box.scrollTop = box.scrollHeight;
  };
  const sendMessage = async () => {
    const message = input.value.trim(); if (!message) return;
    const res = await fetch('/api/chat/send', {method:'POST', headers:{'Content-Type':'application/json','X-CSRF-Token':token}, body: JSON.stringify({message})});
    if (res.ok) { input.value = ''; await loadMessages(); }
  };
  toggle.addEventListener('click', () => { visible = !visible; container.classList.toggle('collapsed', !visible); toggle.setAttribute('aria-expanded', String(visible)); if (icon) icon.textContent = visible ? '⌄' : '›'; if (visible) loadMessages(); });
  send.addEventListener('click', sendMessage); input.addEventListener('keydown', (event) => { if (event.key === 'Enter') sendMessage(); });
  window.setInterval(loadMessages, 5000); loadMessages();
})();
