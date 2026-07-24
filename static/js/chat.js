// Переменная для хранения состояния чата
let chatVisible = true;

function toggleChat() {
    const container = document.getElementById('chat-container');
    const icon = document.querySelector('.toggle-icon');
    if (chatVisible) {
        container.classList.add('collapsed');
        icon.style.transform = 'rotate(-90deg)';
        chatVisible = false;
    } else {
        container.classList.remove('collapsed');
        icon.style.transform = 'rotate(0deg)';
        chatVisible = true;
    }
}

async function loadMessages() {
    if (!chatVisible) return;  // не загружаем, если чат скрыт
    const res = await fetch('/api/chat/messages');
    if (!res.ok) return;
    const messages = await res.json();
    const box = document.getElementById('chat-messages');
    box.innerHTML = '';
    messages.forEach(m => {
        box.innerHTML += `
            <div class="msg">
                <img src="/static/${m.avatar}" alt="avatar">
                <div class="msg-content">
                    <span class="name">${m.display_name}</span>
                    <span class="time">${m.created_at}</span>
                    <div class="text">${m.message}</div>
                </div>
            </div>`;
    });
    box.scrollTop = box.scrollHeight;
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    const msg = input.value.trim();
    if (!msg) return;
    await fetch('/api/chat/send', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: msg})
    });
    input.value = '';
    loadMessages();
}

document.getElementById('send-btn').addEventListener('click', sendMessage);
document.getElementById('message-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
});

// Загружаем сообщения каждые 3 секунды, если чат открыт
setInterval(() => {
    if (chatVisible) loadMessages();
}, 3000);
loadMessages();
