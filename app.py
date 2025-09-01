from flask import Flask, render_template_string, request
import re, dns.resolver, smtplib

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Email Verifier</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --primary: #3f51b5;
            --secondary: #7986cb;
            --bg-light: #f5f7fa;
            --bg-dark: #121212;
            --text-light: #2c3e50;
            --text-dark: #e0e0e0;
            --card-light: #ffffff;
            --card-dark: #1e1e1e;
        }
        body {
            margin: 0;
            font-family: 'Segoe UI', sans-serif;
            background-color: var(--bg-light);
            color: var(--text-light);
            transition: background 0.4s ease, color 0.4s ease;
        }
        body.dark-mode {
            background-color: var(--bg-dark);
            color: var(--text-dark);
        }
        .toggle-btn {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--primary);
            color: white;
            border: none;
            padding: 10px 16px;
            border-radius: 8px;
            cursor: pointer;
            z-index: 1000;
        }
        .hero {
            text-align: center;
            padding: 80px 20px 40px;
            background: linear-gradient(to right, var(--primary), var(--secondary));
            color: white;
            animation: fadeIn 1s ease-in;
        }
        .hero h1 {
            font-size: 48px;
            margin-bottom: 10px;
        }
        .hero p {
            font-size: 20px;
            max-width: 700px;
            margin: 0 auto;
        }
        .container {
            background: var(--card-light);
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
            text-align: center;
            width: 90%;
            max-width: 400px;
            margin: -40px auto 60px;
            transition: background 0.4s ease;
        }
        body.dark-mode .container {
            background: var(--card-dark);
        }
        input[type="email"] {
            padding: 12px;
            width: 80%;
            border: 1px solid #ccc;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 16px;
        }
        button {
            padding: 12px 24px;
            background-color: var(--primary);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s ease;
        }
        button:hover {
            background-color: var(--secondary);
        }
        .result {
            margin-top: 20px;
            font-weight: bold;
            animation: slideUp 0.5s ease-out;
        }
        @keyframes slideUp {
            from {transform: translateY(20px); opacity: 0;}
            to {transform: translateY(0); opacity: 1;}
        }
        .info-section {
            padding: 60px 20px;
        }
        .cards {
            display: flex;
            flex-wrap: wrap;
            justify-content: center;
            gap: 20px;
        }
        .card {
            background: var(--card-light);
            width: 300px;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 6px 12px rgba(0,0,0,0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease, background 0.4s ease;
            animation: fadeInCard 0.6s ease forwards;
        }
        body.dark-mode .card {
            background: var(--card-dark);
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 24px rgba(0,0,0,0.2);
        }
        @keyframes fadeInCard {
            from {opacity: 0; transform: translateY(20px);}
            to {opacity: 1; transform: translateY(0);}
        }
        .card h3 {
            margin-top: 0;
            color: var(--primary);
            font-size: 20px;
        }
        .card p {
            font-size: 15px;
            line-height: 1.5;
        }
        @media (max-width: 768px) {
            .cards {
                flex-direction: column;
                align-items: center;
            }
        }
    </style>
</head>
<body>
    <button class="toggle-btn" onclick="toggleMode()">🌗 Toggle Mode</button>

    <div class="hero">
        <h1>🔍 Email Verifier</h1>
        <p>Check if an email address is valid, properly configured, and reachable.  
        Ideal for developers, recruiters, and cybersecurity analysts who need to verify email authenticity before onboarding users or sending sensitive data.</p>
    </div>

    <div class="container">
        <form method="POST">
            <input type="email" name="email" placeholder="Enter email address" required>
            <br>
            <button type="submit">Verify</button>
        </form>
        {% if result %}
        <div class="result">{{ result }}</div>
        {% endif %}
    </div>

    <div class="info-section">
        <h2 style="text-align:center;">Why Use This Tool?</h2>
        <div class="cards">
            <div class="card">
                <h3>📌 What It Does</h3>
                <p>Performs format checks, domain MX record lookup, and SMTP mailbox verification to ensure the email is real and reachable.</p>
            </div>
            <div class="card">
                <h3>👥 Who It's For</h3>
                <p>Perfect for developers, cybersecurity analysts, HR teams, and anyone who needs to validate email addresses before taking action.</p>
            </div>
            <div class="card">
                <h3>📊 What Results Mean</h3>
                <p><strong>✅ Valid:</strong> Email exists and accepts mail.<br>
                   <strong>⚠️ No MX:</strong> Domain has no mail server.<br>
                   <strong>❌ Invalid:</strong> Format error or mailbox unreachable.</p>
            </div>
        </div>
    </div>

    <script>
        function toggleMode() {
            document.body.classList.toggle('dark-mode');
        }
    </script>
</body>
</html>
"""

def is_valid_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email)

def has_mx_record(domain):
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def smtp_check(email):
    try:
        domain = email.split('@')[1]
        mx_record = dns.resolver.resolve(domain, 'MX')[0].exchange.to_text()
        server = smtplib.SMTP(timeout=10)
        server.connect(mx_record)
        server.helo()
        server.mail('test@example.com')
        code, _ = server.rcpt(email)
        server.quit()
        return code == 250
    except:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        email = request.form['email']
        if not is_valid_format(email):
            result = "❌ Invalid email format."
        elif not has_mx_record(email.split('@')[1]):
            result = "⚠️ Domain has no mail server (MX record)."
        elif smtp_check(email):
            result = "✅ Email address exists and is reachable!"
        else:
            result = "❌ Email address does not exist or is unreachable."
    return render_template_string(HTML_TEMPLATE, result=result)

if __name__ == '__main__':
    app.run(debug=True)