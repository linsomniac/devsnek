"""
Example Flask application for devsnek.

To run:
    devsnek --asgi-app examples.flask_example:app
"""

from flask import Flask, render_template_string

app = Flask(__name__)

# Simple HTML template with WebSocket support for reload notification
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>devsnek Flask Example</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        h1 {
            color: #333;
        }
        .reload-msg {
            display: none;
            background-color: #4CAF50;
            color: white;
            padding: 10px;
            border-radius: 5px;
            position: fixed;
            top: 20px;
            right: 20px;
        }
    </style>
</head>
<body>
    <h1>devsnek Flask Example</h1>
    <p>This is a simple Flask application running with devsnek.</p>
    <p>Try editing this file and watch it auto-reload!</p>
    <p>Current timestamp: {{ timestamp }}</p>
    
    <h2>Features:</h2>
    <ul>
        <li>Automatic HTTPS with LetsEncrypt</li>
        <li>Live reloading</li>
        <li>ASGI application support</li>
        <li>WebSocket capabilities</li>
    </ul>
    
    <div id="reload-msg" class="reload-msg">Page updated!</div>
    
    <script>
        // WebSocket for reload notification
        function connectWebSocket() {
            const ws = new WebSocket(`wss://${window.location.host}/ws`);
            ws.onmessage = function(event) {
                if (event.data === 'reload') {
                    document.getElementById('reload-msg').style.display = 'block';
                    setTimeout(function() {
                        window.location.reload();
                    }, 300);
                }
            };
            ws.onclose = function() {
                // Try to reconnect after a delay
                setTimeout(connectWebSocket, 1000);
            };
        }
        
        // Try to connect WebSocket
        try {
            connectWebSocket();
        } catch (e) {
            console.log('WebSocket connection failed:', e);
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    import time
    return render_template_string(HTML_TEMPLATE, timestamp=time.time())

# For flask<2.0 users, we need this wrapper to make it work with ASGI
try:
    from asgiref.wsgi import WsgiToAsgi
    app = WsgiToAsgi(app)
except ImportError:
    # Flask 2.0+ should work natively with ASGI
    pass

if __name__ == '__main__':
    app.run(debug=True)