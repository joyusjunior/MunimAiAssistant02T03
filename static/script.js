document.addEventListener('DOMContentLoaded', function() {
    const chatbox = document.getElementById('chatbox');
    const userInput = document.getElementById('userInput');
    const sendButton = document.getElementById('sendButton');

    function addMessage(content, isUser, timestamp) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isUser ? 'user-message' : 'bot-message'}`;
        
        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.innerHTML = isUser ? content : 
            `<span class="accounting-badge">AI Accountant</span>${content}`;
        
        const timeDiv = document.createElement('div');
        timeDiv.className = 'message-time';
        timeDiv.textContent = new Date(timestamp).toLocaleTimeString();
        
        messageDiv.appendChild(contentDiv);
        messageDiv.appendChild(timeDiv);
        chatbox.appendChild(messageDiv);
        chatbox.scrollTop = chatbox.scrollHeight;
    }

    function sendMessage() {
        const message = userInput.value.trim();
        if (!message) return;
        
        addMessage(message, true, new Date().toISOString());
        userInput.value = '';
        
        fetch('/api/message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({message: message})
        })
        .then(response => response.json())
        .then(data => {
            addMessage(data.response, false, data.timestamp);
        });
    }

    sendButton.addEventListener('click', sendMessage);
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    // Initial bot greeting
    addMessage("Hello! I'm your accounting assistant. How can I help?", false, new Date().toISOString());
});
