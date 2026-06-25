from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from app.config import settings
from app.database.session import engine, Base
from app.api.router import api_router

# Initialize database models (Creates sqlite database file automatically on start)
Base.metadata.create_all(bind=engine)

# Auto-seed initial Methodist hymns, standing orders, and admin credentials
from app.database.session import SessionLocal
from app.database.seeder import seed_database
db_session = SessionLocal()
try:
    seed_database(db_session)
finally:
    db_session.close()


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI RAG and Hymn Assistant for the Methodist Church Kenya",
    version="1.0.0"
)

# Set up CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include APIs
app.include_router(api_router)

# Mount static files for logo
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
def index_page():
    """
    Embedded, high-fidelity landing dashboard for offline and simple cloud usage.
    Provides instant chat, hymn searches, and administrative document uploads.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Methodist Church Kenya - AI Assistant</title>
        <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary: #1e3a8a;
                --primary-hover: #1e40af;
                --accent: #d97706;
                --bg: #0f172a;
                --card-bg: #1e293b;
                --text: #f8fafc;
                --text-muted: #94a3b8;
                --border: #334155;
            }
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
                font-family: 'Outfit', sans-serif;
            }
            body {
                background-color: var(--bg);
                color: var(--text);
                display: flex;
                min-height: 100vh;
                overflow-x: hidden;
            }
            /* Sidebar Nav */
            aside {
                width: 280px;
                background-color: #0b0f19;
                border-right: 1px solid var(--border);
                display: flex;
                flex-direction: column;
                padding: 24px;
            }
            .brand {
                font-size: 1.25rem;
                font-weight: 700;
                color: var(--text);
                margin-bottom: 32px;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .brand span {
                color: var(--accent);
            }
            .nav-btn {
                background: none;
                border: none;
                color: var(--text-muted);
                padding: 12px 16px;
                text-align: left;
                width: 100%;
                border-radius: 8px;
                font-size: 1rem;
                cursor: pointer;
                transition: 0.3s;
                margin-bottom: 8px;
                font-weight: 600;
            }
            .nav-btn:hover, .nav-btn.active {
                background-color: var(--card-bg);
                color: var(--text);
            }
            .nav-btn.active {
                border-left: 4px solid var(--accent);
            }
            /* Main Area */
            main {
                flex-grow: 1;
                display: flex;
                flex-direction: column;
                padding: 32px;
                max-width: 1200px;
                margin: 0 auto;
                width: calc(100% - 280px);
            }
            header {
                margin-bottom: 24px;
            }
            h1 {
                font-size: 2rem;
                font-weight: 700;
            }
            .subtitle {
                color: var(--text-muted);
                margin-top: 4px;
            }
            .panel {
                display: none;
                background-color: var(--card-bg);
                border: 1px solid var(--border);
                border-radius: 16px;
                padding: 24px;
                flex-grow: 1;
                flex-direction: column;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            }
            .panel.active {
                display: flex;
            }
            /* Chat Interface styling */
            .chat-container {
                display: flex;
                flex-direction: column;
                height: 500px;
            }
            .messages {
                flex-grow: 1;
                overflow-y: auto;
                padding-right: 8px;
                margin-bottom: 16px;
                display: flex;
                flex-direction: column;
                gap: 12px;
            }
            .msg {
                max-width: 75%;
                padding: 12px 16px;
                border-radius: 12px;
                line-height: 1.5;
            }
            .msg.user {
                background-color: var(--primary);
                align-self: flex-end;
            }
            .msg.ai {
                background-color: var(--border);
                align-self: flex-start;
            }
            .citations-block {
                font-size: 0.8rem;
                color: var(--text-muted);
                margin-top: 8px;
                border-t: 1px solid var(--border);
                padding-top: 8px;
            }
            .input-area {
                display: flex;
                gap: 12px;
            }
            input, select, textarea {
                background-color: #0f172a;
                border: 1px solid var(--border);
                color: var(--text);
                padding: 12px 16px;
                border-radius: 8px;
                outline: none;
                font-size: 1rem;
                transition: 0.3s;
            }
            input:focus, select:focus, textarea:focus {
                border-color: var(--accent);
            }
            .chat-input {
                flex-grow: 1;
            }
            .btn {
                background-color: var(--accent);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                font-weight: 600;
                cursor: pointer;
                transition: 0.3s;
            }
            .btn:hover {
                filter: brightness(1.1);
            }
            /* Hymns styling */
            .search-results {
                margin-top: 20px;
                display: flex;
                flex-direction: column;
                gap: 16px;
                overflow-y: auto;
                max-height: 400px;
            }
            .hymn-card {
                background-color: #0f172a;
                padding: 16px;
                border-radius: 8px;
                border: 1px solid var(--border);
            }
            .hymn-card h3 {
                color: var(--accent);
                margin-bottom: 8px;
            }
            .lyrics {
                white-space: pre-wrap;
                font-size: 0.95rem;
                line-height: 1.6;
            }
            /* Form Grid styling */
            .form-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
                margin-bottom: 16px;
            }
            .form-group {
                display: flex;
                flex-direction: column;
                gap: 8px;
            }
        </style>
    </head>
    <body>
        <aside>
            <div class="brand">MCK <span>AI Assistant</span></div>
            <button class="nav-btn active" onclick="switchTab('chat-tab', this)">Chat Assistant</button>
            <button class="nav-btn" onclick="switchTab('admin-tab', this)">Admin Ingestion</button>
        </aside>
        
        <main>
            <!-- Chat Panel -->
            <div id="chat-tab" class="panel active" style="align-items: center; padding-top: 100px;">
                <header style="text-align: center; margin-bottom: 20px;">
                    <img src="/static/logo.png" alt="Methodist Church Kenya Logo" style="height: 120px; margin-bottom: 16px; margin-top: 20px;">
                    <h1 style="font-size: 2.5rem; margin-bottom: 8px;">Methodist AI Assistant</h1>
                    <div class="subtitle" style="font-size: 1.1rem;">Search doctrines, Standing Orders, constitutions, hymns, and scriptures.</div>
                </header>

                <div class="input-area" style="width: 100%; max-width: 750px; margin-bottom: 30px; display: flex; gap: 12px;">
                    <input type="text" id="query-input" class="chat-input" placeholder="Welcome to Methodist church AI how may i help you" onkeypress="handleKeyPress(event)" style="border-radius: 30px; padding: 16px 24px; font-size: 1.1rem; flex-grow: 1;">
                    <button class="btn" onclick="sendChatQuery()" style="border-radius: 30px; padding: 16px 32px; font-size: 1.1rem;">Search</button>
                </div>

                <div class="chat-container" style="width: 100%; max-width: 900px; height: 400px; border: 1px solid var(--border); border-radius: 16px; background-color: #0f172a; padding: 20px; display: none;" id="chat-container-box">
                    <div class="messages" id="chat-messages" style="height: 100%;">
                        <!-- Results appear here -->
                    </div>
                </div>
            </div>


            <!-- Admin Ingest Panel -->
            <div id="admin-tab" class="panel">
                <header>
                    <h1>Admin Document Ingestion</h1>
                    <div class="subtitle">Index Standing Orders, liturgies, and PDFs to the church RAG backend.</div>
                </header>
                <div class="form-grid">
                    <div class="form-group">
                        <label>Document Title</label>
                        <input type="text" id="doc-title" placeholder="e.g. Standing Orders (2018 Edition)">
                    </div>
                    <div class="form-group">
                        <label>Document Category</label>
                        <select id="doc-category">
                            <option value="standing_orders">Standing Orders</option>
                            <option value="hymn_book">Hymn Book</option>
                            <option value="bible">Bible</option>
                            <option value="constitution">Constitution</option>
                            <option value="liturgy">Liturgy</option>
                            <option value="sermon">Sermon / Devotional</option>
                            <option value="circular">Church Circular</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Language</label>
                        <input type="text" id="doc-lang" value="en" placeholder="e.g. en, sw, kik">
                    </div>
                    <div class="form-group">
                        <label>Select PDF / Text File</label>
                        <input type="file" id="doc-file">
                    </div>
                </div>
                <button class="btn" onclick="uploadDocument()">Ingest Document</button>
                <div id="upload-status" style="margin-top: 16px; font-weight: 600;"></div>
            </div>
        </main>

        <script>
            function switchTab(tabId, btn) {
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
                
                document.getElementById(tabId).classList.add('active');
                btn.classList.add('active');
            }

            function handleKeyPress(e) {
                if (e.key === 'Enter') sendChatQuery();
            }

            async function sendChatQuery() {
                const input = document.getElementById('query-input');
                const query = input.value.trim();
                if (!query) return;

                // Show the results box when searching
                document.getElementById('chat-container-box').style.display = 'block';

                const chatMessages = document.getElementById('chat-messages');
                
                // Add user message
                const userMsg = document.createElement('div');
                userMsg.className = 'msg user';
                userMsg.innerText = query;
                chatMessages.appendChild(userMsg);
                input.value = '';
                chatMessages.scrollTop = chatMessages.scrollHeight;

                // Add loading AI indicator
                const loadingMsg = document.createElement('div');
                loadingMsg.className = 'msg ai';
                loadingMsg.innerText = "...Thinking using church sources...";
                chatMessages.appendChild(loadingMsg);
                chatMessages.scrollTop = chatMessages.scrollHeight;

                try {
                    const response = await fetch('/api/v1/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ message: query })
                    });
                    const data = await response.json();
                    
                    loadingMsg.innerText = data.response;
                    
                    // Citations block removed per user request for strict results only
                } catch (err) {
                    loadingMsg.innerText = "Error contacting assistant backend.";
                }
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }



            async function uploadDocument() {
                const title = document.getElementById('doc-title').value;
                const category = document.getElementById('doc-category').value;
                const lang = document.getElementById('doc-lang').value;
                const fileInput = document.getElementById('doc-file');
                const statusDiv = document.getElementById('upload-status');

                if (!title || !fileInput.files[0]) {
                    alert('Please specify title and select a file.');
                    return;
                }

                statusDiv.innerText = 'Uploading and processing file (OCR / Chunking)...';
                statusDiv.style.color = 'var(--text-muted)';

                const formData = new FormData();
                formData.append('title', title);
                formData.append('category', category);
                formData.append('language', lang);
                formData.append('file', fileInput.files[0]);

                try {
                    // For demo/offline, we log in as admin automatically, or bypass.
                    // We mock authentication header for dev convenience using default admin
                    const response = await fetch('/api/v1/admin/upload', {
                        method: 'POST',
                        headers: {
                            // Hardcoded local dev admin token bypass or headers
                            // In real system, JWT returned on login is injected here.
                            'Authorization': 'Bearer ' + localStorage.getItem('token')
                        },
                        body: formData
                    });

                    if (response.status === 401 || response.status === 403) {
                        // Attempt auto-login as local admin for Phase 1 ease-of-use
                        const loginRes = await fetch('/api/v1/auth/register', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                email: 'admin@mck.or.ke',
                                password: 'adminpassword123',
                                full_name: 'Local Admin',
                                role: 'admin'
                            })
                        }).catch(() => null);

                        let tokenRes = null;
                        if (loginRes && loginRes.status === 200) {
                            tokenRes = await loginRes.json();
                        } else {
                            const retryRes = await fetch('/api/v1/auth/login', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({
                                    email: 'admin@mck.or.ke',
                                    password: 'adminpassword123'
                                })
                            });
                            tokenRes = await retryRes.json();
                        }

                        if (tokenRes && tokenRes.access_token) {
                            localStorage.setItem('token', tokenRes.access_token);
                            // Retry upload once
                            statusDiv.innerText = 'Authenticated. Retrying upload...';
                            const retryUpload = await fetch('/api/v1/admin/upload', {
                                method: 'POST',
                                headers: { 'Authorization': 'Bearer ' + tokenRes.access_token },
                                body: formData
                            });
                            const retryData = await retryUpload.json();
                            if (retryUpload.status === 200) {
                                statusDiv.innerText = retryData.message;
                                statusDiv.style.color = '#10b981';
                            } else {
                                statusDiv.innerText = 'Failed to ingest: ' + (retryData.detail || 'Unknown error');
                                statusDiv.style.color = '#ef4444';
                            }
                        } else {
                            statusDiv.innerText = 'Unauthorized. Please login first.';
                            statusDiv.style.color = '#ef4444';
                        }
                        return;
                    }

                    const data = await response.json();
                    if (response.status === 200) {
                        statusDiv.innerText = data.message;
                        statusDiv.style.color = '#10b981';
                    } else {
                        statusDiv.innerText = 'Failed: ' + (data.detail || 'Error');
                        statusDiv.style.color = '#ef4444';
                    }
                } catch (err) {
                    statusDiv.innerText = 'Error connecting to upload API.';
                    statusDiv.style.color = '#ef4444';
                }
            }
        </script>
    </body>
    </html>
    """
    return html_content
