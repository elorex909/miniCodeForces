from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import subprocess
import os
import json
import time
import random
import string
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import logging
import socket
import requests 
import re
from collections import Counter

# Load environment variables FIRST to get SECRET_KEY/ADMIN_PASS
load_dotenv()

# Setup basic console logging for debugging purposes
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
# CRITICAL FIX for Session Stability: Use a very strong, fixed key.
app.secret_key = os.getenv('SECRET_KEY', 'VERY_STRONG_AND_STABLE_MINI_CF_KEY_A1B2C3D4E5F6G7H8')
app.permanent_session_lifetime = timedelta(days=1)

# --- Configuration Constants ---
LEVELS = ['A', 'B', 'C', 'D', 'E']
LEVEL_MAP = {level: i for i, level in enumerate(LEVELS)}
DEFAULT_RUNTIME_LIMIT_SECONDS = 2.0  # Default execution time limit

ADMIN_USER = os.getenv('ADMIN_USERNAME', 'elorex909')
ADMIN_PASS_HASH = generate_password_hash(os.getenv('ADMIN_PASSWORD', 'A7s6d5147852369@#'))

# ----- Files configuration -----
USERS_FILE = "users.json"
QUESTIONS_FILE = "questions.json"
CONTEST_CONFIG_FILE = "contest_config.json"


# ------------------ Helpers ------------------

def enhanced_ai_detection(code, problem_description=""):
    """
    Enhanced AI detection with multiple heuristics
    """
    flags = []
    reasons = []
    
    # 1. Code style analysis
    lines = code.split('\n')
    code_lines = [line for line in lines if line.strip() and not line.strip().startswith('//')]
    
    # Check for excessive comments or generic variable names
    comment_ratio = len([l for l in lines if '//' in l]) / max(len(lines), 1)
    if comment_ratio > 0.3:
        flags.append("HIGH_COMMENT_RATIO")
        reasons.append("Unnaturally high comment-to-code ratio")
    
    # 2. Variable naming patterns
    generic_vars = re.findall(r'\b(temp|var|value|data|result|input|output)\b', code, re.IGNORECASE)
    if len(generic_vars) > 5:
        flags.append("GENERIC_NAMING")
        reasons.append("Excessive use of generic variable names")
    
    # 3. Complexity analysis
    if len(code_lines) < 15 and "complexity" in problem_description.lower():
        flags.append("OVERSIMPLIFIED")
        reasons.append("Solution appears oversimplified for problem complexity")
    
    # 4. Common AI patterns
    ai_patterns = [
        r'#include\s*<bits/stdc\+\+\.h>',
        r'using\s+namespace\s+std\s*;',
        r'int\s+main\s*\(\s*\)'
    ]
    
    ai_score = 0
    for pattern in ai_patterns:
        if re.search(pattern, code):
            ai_score += 1
    
    if ai_score >= 2:
        flags.append("AI_STYLE")
        reasons.append("Code structure matches common AI-generated patterns")
    
    # 5. Code length analysis
    if len(code_lines) > 100:
        flags.append("LONG_CODE")
        reasons.append(f"Code length is excessive ({len(code_lines)} lines)")
    elif len(code_lines) < 10:
        flags.append("SHORT_CODE")
        reasons.append(f"Code appears too short ({len(code_lines)} lines) for competitive programming")
    
    # Decision logic
    if len(flags) >= 2:
        return True, f"Multiple flags detected: {', '.join(flags)}. Reasons: {'; '.join(reasons)}"
    elif "AI_STYLE" in flags and len(code_lines) > 50:
        return True, "Strong AI pattern match"
    elif "LONG_CODE" in flags and comment_ratio > 0.2:
        return True, "Suspicious combination of long code and high comments"
    
    return False, "No significant AI patterns detected"


def run_code_via_piston(code, input_data, runtime_limit):
    """
    Run C++ code using Piston API (open source)
    """
    try:
        payload = {
            "language": "cpp",
            "version": "10.2.0",
            "files": [{"content": code}],
            "stdin": input_data,
            "compile_timeout": 10000,
            "run_timeout": int(runtime_limit * 1000)
        }
        
        response = requests.post(
            'https://emkc.org/api/v2/piston/execute',
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            run_result = result.get('run', {})
            
            # Check for compilation errors
            compile_output = result.get('compile', {}).get('output', '').strip()
            if compile_output and 'error' in compile_output.lower():
                return "Compile Error", compile_output, 0.0
            
            if run_result.get('signal') == 'SIGKILL':
                return "Time Limit Exceeded", "Process killed due to timeout", runtime_limit
            
            output = run_result.get('output', '').strip()
            exit_code = run_result.get('code', 0)
            
            if exit_code == 0:
                return "Accepted", output, float(run_result.get('time', 0.0))
            else:
                return "Runtime Error", f"Exit code {exit_code}: {output}", float(run_result.get('time', 0.0))
                
        else:
            return "System Error", f"Piston API error: {response.status_code}", 0.0
            
    except requests.exceptions.Timeout:
        return "Time Limit Exceeded", "Execution timeout", runtime_limit
    except Exception as e:
        logger.error(f"Piston API Error: {e}")
        return "System Error", f"Compiler service unavailable: {e}", 0.0


def run_code_via_jdoodle(code, input_data, runtime_limit):
    """
    Run C++ code using JDoodle Compiler API
    """
    try:
        # JDoodle API credentials (you need to sign up for free)
        client_id = os.getenv('JDOODLE_CLIENT_ID', '')
        client_secret = os.getenv('JDOODLE_CLIENT_SECRET', '')
        
        # If no JDoodle credentials, fall back to Piston
        if not client_id or not client_secret:
            return run_code_via_piston(code, input_data, runtime_limit)
        
        payload = {
            "script": code,
            "stdin": input_data,
            "language": "cpp",
            "versionIndex": "0",
            "compileOnly": False
        }
        
        headers = {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest'
        }
        
        response = requests.post(
            'https://api.jdoodle.com/v1/execute',
            json=payload,
            headers=headers,
            auth=(client_id, client_secret),
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            if 'error' in result:
                return "Compile Error", result['error'], 0.0
            
            output = result.get('output', '').strip()
            status = result.get('statusCode', 200)
            
            if status == 200:
                return "Accepted", output, float(result.get('cpuTime', 0.0))
            else:
                return "Runtime Error", output, 0.0
                
        else:
            return "System Error", f"API returned {response.status_code}", 0.0
            
    except requests.exceptions.Timeout:
        return "Time Limit Exceeded", "Execution timeout", runtime_limit
    except Exception as e:
        logger.error(f"JDoodle API Error: {e}")
        return "System Error", f"Compiler service unavailable: {e}", 0.0


# NEW HELPER: Runs code using an external API
def run_code_via_api(code, input_data, runtime_limit):
    """
    Runs C++ code against real online compiler APIs
    """
    # Try Piston API first (free, no registration required)
    return run_code_via_piston(code, input_data, runtime_limit)


def get_wan_ip():
    """Attempts to determine the public IP address for external access. (Simplified)"""
    return "Localhost/Debug IP" 


def load_users():
    """Loads user data from USERS_FILE."""
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_users(u):
    """Saves user data to USERS_FILE."""
    with open(USERS_FILE, "w") as f:
        json.dump(u, f, indent=2)


def load_questions():
    """Loads question data from QUESTIONS_FILE."""
    try:
        with open(QUESTIONS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_questions(q):
    """Saves question data to QUESTIONS_FILE."""
    with open(QUESTIONS_FILE, "w") as f:
        json.dump(q, f, indent=2)


def load_contest_config():
    """Loads contest configuration from CONTEST_CONFIG_FILE."""
    try:
        with open(CONTEST_CONFIG_FILE, "r") as f:
            config = json.load(f)

        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

        return {
            'is_active': config.get('is_active', False),
            'start_time': config.get('start_time', now_str),
            'end_time': config.get('end_time', now_str)
        }
    except (FileNotFoundError, json.JSONDecodeError):
        default_config = {
            "is_active": False,
            "start_time": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            "end_time": (datetime.now(timezone.utc) + timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(CONTEST_CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        return default_config


def save_contest_config(config):
    """Saves contest configuration."""
    with open(CONTEST_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


def check_contest_status():
    """Checks if the contest is currently active based on system time (UTC)."""
    config = load_contest_config()

    if not config.get('is_active', False):
        return "OFFLINE", "Contest is currently **offline**."

    try:
        start = datetime.strptime(config.get('start_time'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        end = datetime.strptime(config.get('end_time'), '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        if now < start:
            remaining = start - now
            return "UPCOMING", f"Contest starts in: **{str(remaining).split('.')[0]}**"
        elif now >= start and now < end:
            remaining = end - now
            return "ACTIVE", f"Contest ends in: **{str(remaining).split('.')[0]}**"
        else:
            return "FINISHED", "Contest has **finished**."

    except ValueError:
        logger.error("Contest time format error.")
        return "ERROR", "Invalid time format in contest configuration."


def generate_temp_name(length=12):
    """Generates a secure, random string for temporary file names."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))


def get_user_status_for_question(username, qid_str):
    """Retrieves the best submission status for a user on a specific question."""
    users = load_users()
    user_data = users.get(username, {})
    if 'submissions' in user_data and qid_str in user_data['submissions']:
        return user_data['submissions'][qid_str].get('best_status', 'Not Attempted')
    return 'Not Attempted'


def grant_badge(username, badge_name):
    """Grants a badge to a user if they don't already have it."""
    users = load_users()
    if username not in users: return

    if 'badges' not in users[username]:
        users[username]['badges'] = []

    if badge_name not in users[username]['badges']:
        users[username]['badges'].append(badge_name)
        save_users(users)
        flash(f"🎉 You earned the badge: {badge_name}!", "success")


def get_initial_questions_data():
    """Generates a stable set of 50 questions for automatic initialization."""
    questions = {}
    q_id_counter = 1

    base_desc = {
        'A': 'Basic I/O: Read two integers, A and B, and print their sum. Tests basic I/O.',
        'B': 'Implementation: Given N strings, count how many begin with a vowel. Tests string manipulation and loops.',
        'C': 'STL/Sorting: Given N integers, output the second smallest distinct number. Tests std::set and sorting.',
        'D': 'N log N: Given a large array A, answer Q range sum queries efficiently. Tests Prefix Sum and simple query logic.',
        'E': 'Advanced DP: Given N items with weights and values, find the maximum value you can carry with capacity W. (Knapsack 0/1)'
    }

    time_limits = {'A': 5, 'B': 8, 'C': 10, 'D': 12, 'E': 15}
    runtime_limits = {'A': 1.0, 'B': 1.5, 'C': 2.0, 'D': 3.0, 'E': 4.0}
    memory_limits = {'A': 128, 'B': 128, 'C': 256, 'D': 512, 'E': 512}

    for level in LEVELS:
        for i in range(1, 11):
            title = f"{level}{i}. Problem {i} of Level {level} (Sample)"

            if level == 'A':
                q_desc = base_desc[level]
                test_cases = [{"input": "1 2", "expected_output": "3"}, {"input": "100 50", "expected_output": "150"}]
            elif level == 'E':
                q_desc = f"{base_desc[level]} Use DP to solve the 0/1 Knapsack problem."
                test_cases = [{"input": "3 50\n60 10\n100 20\n120 30", "expected_output": "220"}]
            else:
                q_desc = base_desc[level] + f" Find the max value in an array."
                test_cases = [{"input": "5 1 9 4 7 3", "expected_output": "9"}]

            questions[str(q_id_counter)] = {
                "id": q_id_counter,
                "title": title,
                "level": level,
                "time_limit_minutes": time_limits[level],
                "runtime_limit_seconds": runtime_limits[level],
                "memory_limit_mb": memory_limits[level],
                "description": q_desc,
                "test_cases": test_cases
            }
            q_id_counter += 1

    return questions


def initialize_files():
    """Ensures all necessary data files exist and loads CORE_QUESTIONS_DATA."""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

    if not os.path.exists(QUESTIONS_FILE):
        full_questions_data = get_initial_questions_data()
        with open(QUESTIONS_FILE, "w") as f:
            json.dump(full_questions_data, f, indent=2)
            logger.info("Initialized QUESTIONS_FILE with 50 default problems.")

    if not os.path.exists(CONTEST_CONFIG_FILE):
        load_contest_config()


# CRITICAL FIX: Ensure files are initialized BEFORE the app starts handling requests
initialize_files()


# ------------------ Template Functions ------------------
def render_base(content, **kwargs):
    """Renders main content inside the base HTML structure, including MathJax."""
    base = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Mini Codeforces // Access Granted</title>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.css">
  
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/theme/monokai.min.css"> 
  
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/codemirror.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/mode/clike/clike.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.5/addon/edit/closebrackets.min.js"></script>

  <script type="text/javascript" id="MathJax-script" async
    src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js">
  </script>
  <script>
    MathJax = {
      tex: { inlineMath: [['$', '$'], ['\\(', '\\)']] },
      svg: { fontCache: 'global' }
    };
  </script>
  <style>
    /* -------------------- NEW CYBERPUNK/TERMINAL THEME STYLES -------------------- */
    * { box-sizing: border-box; }
    /* Primary Colors */
    :root {
        --color-bg: #030616;
        --color-main: #00ffaa; /* Neon Green */
        --color-accent: #ff00ff; /* Neon Magenta */
        --color-text: #e0f2f1;
        --color-card: #0d1a33;
        --color-border: #0077ff;
    }
    body { 
        background: var(--color-bg); 
        color: var(--color-text); 
        font-family: 'Courier New', monospace; 
        margin:0; 
        padding:20px; 
    }
    .container { max-width:1200px; margin:auto; }
    header { 
        display:flex; 
        justify-content:space-between; 
        align-items:center; 
        flex-wrap:wrap; 
        gap:10px; 
        padding-bottom: 10px;
        border-bottom: 2px solid var(--color-border);
        box-shadow: 0 2px 10px rgba(0, 119, 255, 0.5);
    }
    h1 { color: var(--color-main); text-shadow: 0 0 5px var(--color-main); margin:0; }
    h3 { color: var(--color-accent); margin-top:0; border-bottom: 1px dashed var(--color-card); padding-bottom: 5px;}
    h4 { color: var(--color-border); margin-top:20px; }

    /* Card/Content Blocks */
    .card { 
        background: var(--color-card); 
        padding:20px; 
        border-radius:0; 
        margin-top:15px; 
        box-shadow: 0 0 15px rgba(0, 255, 170, 0.2);
        border: 1px solid var(--color-border);
    }
    .notice { background: var(--color-bg); color: var(--color-accent); border: 1px dashed var(--color-accent); }
    
    /* Inputs */
    label { display:block; margin-bottom:5px; font-weight:bold; color: var(--color-main); }
    input, textarea, select { 
        width:100%; 
        padding:10px; 
        border-radius:0; 
        border:1px solid var(--color-border); 
        background: var(--color-bg); 
        color: var(--color-main); 
        font-family: inherit; 
        box-shadow: inset 0 0 5px rgba(0, 255, 170, 0.5);
    }
    input:focus, textarea:focus, select:focus { outline:none; border-color: var(--color-accent); }
    
    /* Buttons */
    button { 
        padding:10px 18px; 
        border-radius:0; 
        border: 2px solid var(--color-main);
        background: rgba(0, 255, 170, 0.1); 
        color: var(--color-main); 
        font-weight:bold; 
        cursor:pointer; 
        transition: all 0.2s; 
        text-shadow: 0 0 3px var(--color-main);
    }
    button:hover { 
        background: var(--color-main); 
        color: var(--color-bg); 
        box-shadow: 0 0 10px var(--color-main);
    }
    .btn-danger { background: rgba(255, 0, 0, 0.2); color: #ff6666; border-color: #ff6666; }
    .btn-danger:hover { background: #ff6666; color: var(--color-bg); }
    .btn-warning { background: rgba(255, 165, 0, 0.2); color: #ffaa00; border-color: #ffaa00; }
    .btn-primary { border-color: var(--color-border); color: var(--color-border); }

    /* Tables */
    table { border: 1px dashed var(--color-card); }
    th { background: var(--color-card); padding:12px; border-bottom: 2px solid var(--color-main); }
    td { padding:10px; border-bottom:1px solid #1a3366; }
    
    /* Statuses (New Icons) */
    .accepted, .status-AC { color: var(--color-main); font-weight:bold; font-size:18px; }
    .wrong, .status-WA, .status-RE, .status-TLE, .status-CE { color: #ff4444; font-weight:bold; font-size:18px; }
    .status-NA { color: #556699; }
    .status-Cheated { color: var(--color-accent); }

    .result-icon { margin-right: 8px; font-weight: bold; }
    .result-icon-AC { color: var(--color-main); }
    .result-icon-FAIL { color: #ff4444; }

    /* Flash Messages */
    .flash-messages { border: 1px solid; border-left: 4px solid; margin-top: 15px; border-radius: 0; }
    .flash-error { background:#2a0000; color:#ff8888; border-left-color:#ff0000; }
    .flash-success { background:#002a14; color:#99ff99; border-left-color:var(--color-main); }

    /* Other elements */
    pre { background: #000000; border: 1px dashed var(--color-main); color: var(--color-main); }
    .contest-active { background: #003a27; color: var(--color-main); }
    .contest-upcoming { background: #4a3800; color: #ffaa00; }
    
    /* AI Notice (Retained but simplified) */
    .ai-notice { background: #1a0033; color: var(--color-accent); border-color: var(--color-accent); text-shadow: none; }
    
    /* Grid layouts */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; }
    .grid-4 { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 15px; }
    
    @media (max-width: 768px) {
        .grid-2, .grid-3, .grid-4 { grid-template-columns: 1fr; }
    }
    
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>[[ Mini Codeforces // Access Granted ]]</h1>
      <div>
        {% if session.get('role') == 'admin' %}
          <span class="small">User: ADMIN (LVL {{ session.get('user_level') }})</span>
          <a href="{{ url_for('admin_dashboard') }}"><button>ADMIN PANEL</button></a>
          <a href="{{ url_for('logout') }}"><button>LOGOUT</button></a>
        {% elif session.get('role') == 'user' %}
          <span class="small">User: {{ session.get('username') }} (LVL {{ session.get('user_level') }})</span>
          <a href="{{ url_for('questions_list') }}"><button>QUESTIONS</button></a>
          <a href="{{ url_for('logout') }}"><button>LOGOUT</button></a>
        {% else %}
          <a href="{{ url_for('login_page') }}"><button>LOGIN</button></a>
        {% endif %}
      </div>
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for category, message in messages %}
          <div class="card flash-messages {% if 'error' in category.lower() or '❌' in message %}flash-error{% elif 'success' in category.lower() or '✅' in message %}flash-success{% endif %}">
            {{ message | replace('✅', '✔️') | replace('❌', 'F!L') }}
          </div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {{ content|safe }}

    <p class="notice">WARNING // This code relies on remote compilation services. Do NOT run user code on an unsecured public host.</p>
    <p class="small" style="text-align: center;">-- System Build by Ahmed Hassan --</p>
  </div>
</body>
</html>
"""
    return render_template_string(base, content=content, session=session, LEVELS=LEVELS, **kwargs)


# ------------------ Routes ------------------
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    """Handles user and admin login authentication."""
    if request.method == 'GET':
        content = """
  <div class="card" style="max-width:500px; margin:50px auto;">
    <h3>// AUTHENTICATION REQUIRED //</h3>
    <form method="POST" action="/login">
      <div class="form-group">
        <label>USERNAME</label>
        <input name="username" required autocomplete="username">
      </div>
      <div class="form-group">
        <label>PASSWORD</label>
        <input name="password" type="password" required autocomplete="current-password">
      </div>
      <button type="submit" style="width:100%;">LOGIN</button>
    </form>
    <p class="small" style="margin-top:15px; text-align:center;">User database maintained by Administrator.</p>
  </div>
"""
        return render_base(content)

    # POST: Process login credentials
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    # Admin login check
    if username == ADMIN_USER:
        if check_password_hash(ADMIN_PASS_HASH, password):
            session.permanent = True
            session['username'] = username
            session['role'] = 'admin'
            session['user_level'] = 'Admin'
            flash("✔️ Access Granted: Administrator Login", "success")
            logger.info(f"Admin login successful: {username}")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("F!L Invalid admin password", "error")
            return redirect(url_for('login_page'))

    # Normal user login
    users = load_users()
    if username in users:
        if check_password_hash(users[username]['pw_hash'], password):
            session.permanent = True
            session['username'] = username
            session['role'] = 'user'
            session['user_level'] = users[username].get('level', 'A')

            if 'badges' not in users[username].get('badges', []):
                grant_badge(username, "First Timer")

            flash(f"✔️ Login Success: Welcome {username}! Your level is {session['user_level']}.", "success")
            logger.info(f"User login successful: {username}")
            return redirect(url_for('questions_list'))
        else:
            flash("F!L Invalid password", "error")
            return redirect(url_for('login_page'))
    else:
        flash("F!L Username not found", "error")
        return redirect(url_for('login_page'))


@app.route('/logout')
def logout():
    """Clears the session and redirects to the login page."""
    username = session.get('username', 'Unknown')
    session.clear()
    flash("✔️ Session Terminated Successfully", "success")
    logger.info(f"User logged out: {username}")
    return redirect(url_for('login_page'))


@app.route('/admin/')
@app.route('/admin')
def admin_dashboard():
    """Admin dashboard to manage users, questions, and contest schedule."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    users = load_users()
    qdict = load_questions()
    qs = [qdict[k] for k in sorted(qdict.keys(), key=lambda x: int(x))]
    config = load_contest_config()
    status, message = check_contest_status()

    # Prepare user tracking data
    user_submission_data = {}
    for uname, udata in users.items():
        if uname != ADMIN_USER:
            user_submission_data[uname] = {
                'level': udata.get('level', 'A'),
                'total_solved': sum(1 for qid, sub_info in udata.get('submissions', {}).items() if
                                    sub_info.get('best_status') in ['Accepted', 'Cheated']), 
                'submissions': udata.get('submissions', {})
            }

    inner_content = f"""
  <div class="card">
    <h3>// ADMIN PANEL //</h3>

    <h4>[ System Status: Contest Schedule ]</h4>
    <div class="card contest-{status.lower()}" style="margin-bottom: 20px;">
        Contest Status: <strong>{status}</strong> | {message} (All times are UTC)
    </div>

    <form method="POST" action="{url_for('admin_set_contest')}" style="margin-bottom: 30px;">
        <div class="grid-3">
            <div class="form-group">
                <label>Active Status</label>
                <select name="is_active">
                    <option value="True" {'selected' if config['is_active'] else ''}>Active</option>
                    <option value="False" {'selected' if not config['is_active'] else ''}>Offline</option>
                </select>
            </div>
            <div class="form-group">
                <label>Start Time (YYYY-MM-DD HH:MM:SS)</label>
                <input name="start_time" value="{config['start_time']}" type="text" placeholder="e.g., 2025-12-31 18:00:00" required>
            </div>
            <div class="form-group">
                <label>End Time (YYYY-MM-DD HH:MM:SS)</label>
                <input name="end_time" value="{config['end_time']}" type="text" placeholder="e.g., 2025-12-31 20:00:00" required>
            </div>
        </div>
        <button type="submit" class="btn-warning">UPDATE SCHEDULE</button>
    </form>

    <hr>

    <div class="grid-2">
      <div>
        <h4>[ User Management: Add New ]</h4>
        <form method="POST" action="{url_for('admin_add_user')}">
          <div class="form-group">
            <label>USERNAME</label>
            <input name="new_username" required autocomplete="off">
          </div>
          <div class="form-group">
            <label>PASSWORD</label>
            <input name="new_password" type="password" required autocomplete="new-password">
          </div>
          <div class="form-group">
            <label>USER LEVEL</label>
            <select name="user_level" required>
                {''.join(f'<option value="{level}" {"selected" if level == "A" else ""}>{level}</option>' for level in LEVELS)}
            </select>
          </div>
          <button type="submit" class="btn-primary">ADD USER</button>
        </form>
      </div>

      <div>
        <h4>[ Problem Set: Add New ]</h4>
        <p class="small" style="color:#fcd34d;">NOTE: Use a new line for each Input/Output pair, separated by "###" (e.g., Input###Output).</p>
        <form method="POST" action="{url_for('admin_add_question')}">
          <div class="form-group">
            <label>PROBLEM TITLE</label>
            <input name="title" required>
          </div>
          <div class="grid-4">
            <div class="form-group">
                <label>LEVEL</label>
                <select name="q_level" required>
                    {''.join(f'<option value="{level}" class="level-{level}" {"selected" if level == "A" else ""}>{level}</option>' for level in LEVELS)}
                </select>
            </div>
            <div class="form-group">
                <label>TIME LIMIT (MIN)</label>
                <input name="time_limit_minutes" type="number" min="1" max="15" value="15" required>
            </div>
            <div class="form-group">
                <label>RUNTIME (S)</label>
                <input name="runtime_limit_seconds" type="number" step="0.1" min="0.1" max="10" value="2.0" required>
            </div>
            <div class="form-group">
                <label>MEMORY (MB)</label>
                <input name="memory_limit_mb" type="number" min="128" max="512" value="256" required>
            </div>
          </div>
          <div class="form-group">
            <label>DESCRIPTION (Use $A^B$ for math)</label>
            <textarea name="description" rows="3" required></textarea>
          </div>
          <div class="form-group">
            <label>TEST CASES (Input###Output)</label>
            <textarea name="test_cases" rows="4" required>// Example:
1 2###3
Hello###Hello</textarea>
          </div>
          <button type="submit" class="btn-primary">ADD PROBLEM</button>
        </form>
      </div>
    </div>

    <hr>

    <h4>[ Submission Tracking ]</h4>
    <table>
      <tr>
        <th>USERNAME</th>
        <th>LEVEL</th>
        <th>SOLVED</th>
        {''.join(f'<th>Q{q["id"]}</th>' for q in qs)}
        <th>ACTION</th>
      </tr>
      {''.join(f'''
        <tr>
          <td>{uname}</td>
          <td class="level-{udata["level"]}">{udata["level"]}</td>
          <td>{udata["total_solved"]}</td>
          {''.join(f"""
            <td class="status-{udata['submissions'].get(str(q['id']), {}).get('best_status', 'Not Attempted').split(' ')[0] if udata['submissions'].get(str(q['id']), {}).get('best_status') != 'Not Attempted' else 'NA'}">
              {udata['submissions'].get(str(q['id']), {}).get('best_status', 'Not Attempted').split(' ')[0] if udata['submissions'].get(str(q['id']), {}).get('best_status') != 'Not Attempted' else '-'}
              
              {f'<span title="{udata["submissions"].get(str(q["id"]), {}).get("ai_reason", "AI Flagged")}" class="ai-flag-admin">🚨 CHEATED</span>' if udata['submissions'].get(str(q['id']), {}).get('best_status') == 'Cheated' else ''}
            </td>
          """ for q in qs)}
          <td>
            <a href="{url_for('admin_edit_user', username=uname)}"><button class="btn-primary">Edit</button></a>
            <a href="{url_for('admin_delete_user', username=uname)}" onclick="return confirm('Confirm user deletion: {uname}?')">
              <button class="btn-danger">DELETE</button>
            </a>
          </td>
        </tr>
      ''' for uname, udata in user_submission_data.items() if uname != ADMIN_USER)}
    </table>
  </div>
"""
    rendered_content = render_template_string(inner_content, session=session, LEVELS=LEVELS)
    return render_base(rendered_content)


@app.route('/admin/set_contest', methods=['POST'])
def admin_set_contest():
    """Handles setting the global contest start/end times and active status."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    is_active_str = request.form['is_active']
    start_time_str = request.form['start_time']
    end_time_str = request.form['end_time']

    try:
        if is_active_str == 'True':
            datetime.strptime(start_time_str, '%Y-%m-%d %H:%M:%S')
            datetime.strptime(end_time_str, '%Y-%m-%d %H:%M:%S')

        new_config = {
            'is_active': is_active_str == 'True',
            'start_time': start_time_str,
            'end_time': end_time_str
        }
        save_contest_config(new_config)
        flash("✔️ Contest schedule updated.", "success")

    except ValueError:
        flash("F!L Error: Date/time format must be YYYY-MM-DD HH:MM:SS.", "error")
    except Exception as e:
        logger.error(f"Error saving contest config: {e}")
        flash("F!L An unexpected error occurred while saving configuration.", "error")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    """Handles adding a new user with a specified level."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    new_username = request.form['new_username'].strip()
    new_password = request.form['new_password'].strip()
    new_level = request.form['user_level'].upper()

    if not new_username or not new_password or new_level not in LEVELS:
        flash("F!L All fields are required and Level must be valid (A-E)", "error")
        return redirect(url_for('admin_dashboard'))

    users = load_users()

    if new_username in users:
        flash("F!L User already exists", "error")
        return redirect(url_for('admin_dashboard'))

    pw_hash = generate_password_hash(new_password)
    users[new_username] = {"pw_hash": pw_hash, "level": new_level, "submissions": {}, "badges": []}
    save_users(users)
    flash(f"✔️ User {new_username} added successfully with Level {new_level}", "success")
    logger.info(f"Admin {session.get('username')} added new user: {new_username} (Level {new_level})")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_user/<username>', methods=['GET', 'POST'])
def admin_edit_user(username):
    """Allows admin to edit a user's level and reset password."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    users = load_users()
    user_data = users.get(username)

    if not user_data or username == ADMIN_USER:
        flash("F!L User not found or cannot edit main admin.", "error")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        new_level = request.form['new_level'].upper()
        new_password = request.form['new_password'].strip()

        if new_level not in LEVELS:
            flash("F!L Invalid level selected.", "error")
            return redirect(url_for('admin_edit_user', username=username))

        user_data['level'] = new_level

        if new_password:
            # Hash the new password if provided
            user_data['pw_hash'] = generate_password_hash(new_password)
            flash(f"✔️ User {username} updated, password reset.", "success")
        else:
            flash(f"✔️ User {username} level updated to {new_level}.", "success")

        save_users(users)

        if session.get('username') == username:
            session['user_level'] = new_level

        return redirect(url_for('admin_dashboard'))

    # GET request
    current_level = user_data.get('level', 'A')

    content = f"""
    <div class="card" style="max-width:600px; margin:50px auto;">
        <h3>// EDIT USER: {username} //</h3>
        <form method="POST" action="{url_for('admin_edit_user', username=username)}">
            <div class="form-group">
                <label>CURRENT LEVEL</label>
                <select name="new_level" required>
                    {
    ''.join(f'<option value="{level}" {"selected" if level == current_level else ""}>{level}</option>' for level in LEVELS)
    }
                </select>
            </div>
            <div class="form-group">
                <label>NEW PASSWORD (Leave blank to keep old password)</label>
                <input name="new_password" type="password">
            </div>
            <button type="submit" class="btn-primary" style="width:100%;">SAVE CHANGES</button>
        </form>
    </div>
    """
    return render_base(content)


@app.route('/admin/add_question', methods=['POST'])
def admin_add_question():
    """Handles adding a new question with multiple test cases, level, and time limit."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    title = request.form['title'].strip()
    q_level = request.form['q_level'].upper()
    desc = request.form['description'].strip()
    test_cases_raw = request.form['test_cases']

    try:
        time_limit_minutes = int(request.form.get('time_limit_minutes', 15))
        if not (1 <= time_limit_minutes <= 15):
            flash("F!L Time Limit (Minutes) must be between 1 and 15 minutes.", "error")
            return redirect(url_for('admin_dashboard'))
    except ValueError:
        flash("F!L Time Limit (Minutes) must be a valid number.", "error")
        return redirect(url_for('admin_dashboard'))

    try:
        runtime_limit_seconds = float(request.form.get('runtime_limit_seconds', 2.0))
        if not (0.1 <= runtime_limit_seconds <= 10.0):
            flash("F!L Runtime Limit (Seconds) must be between 0.1 and 10.0 seconds.", "error")
            return redirect(url_for('admin_dashboard'))
    except ValueError:
        flash("F!L Runtime Limit (Seconds) must be a valid number.", "error")
        return redirect(url_for('admin_dashboard'))

    memory_limit_mb = int(request.form.get('memory_limit_mb', 256))

    if not title or not desc or not test_cases_raw or q_level not in LEVELS:
        flash("F!L All required fields are missing or Level is invalid (A-E)", "error")
        return redirect(url_for('admin_dashboard'))

    qdict = load_questions()
    numeric_keys = [int(k) for k in qdict.keys() if k.isdigit()]
    next_id = max(numeric_keys) + 1 if numeric_keys else 1

    # Process "Input###Output" strings into structured test cases
    test_cases_list = []
    lines = test_cases_raw.strip().split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        parts = line.split('###', 1)
        if len(parts) == 2:
            test_cases_list.append({
                "input": parts[0].strip(),
                "expected_output": parts[1].strip()
            })
        else:
            flash(f"F!L Error in Test Case line {i + 1}: Must be 'Input###ExpectedOutput'", "error")
            return redirect(url_for('admin_dashboard'))

    if not test_cases_list:
        flash("F!L At least one valid test case is required.", "error")
        return redirect(url_for('admin_dashboard'))

    qdict[str(next_id)] = {
        "id": next_id,
        "title": title,
        "level": q_level,
        "time_limit_minutes": time_limit_minutes,
        "runtime_limit_seconds": runtime_limit_seconds,
        "memory_limit_mb": memory_limit_mb,
        "description": desc,
        "test_cases": test_cases_list
    }
    save_questions(qdict)
    flash(f"✔️ Level {q_level} Problem {next_id} added.", "success")
    logger.info(f"Admin {session.get('username')} added question: {title} (Level {q_level})")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/edit_question/<int:qid>', methods=['GET', 'POST'])
def admin_edit_question(qid):
    """Allows admin to edit a question's details, level, time limit, and test cases."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    qdict = load_questions()
    qid_str = str(qid)
    q = qdict.get(qid_str)

    if not q:
        flash("F!L Problem not found.", "error")
        return redirect(url_for('admin_dashboard'))

    # Helper function to convert list of test cases back to "Input###Output" string
    def format_test_cases_to_text(test_cases_list):
        return '\n'.join(f"{tc.get('input', '')}###{tc.get('expected_output', '')}" for tc in test_cases_list)

    current_test_cases_raw = format_test_cases_to_text(q.get('test_cases', []))

    if request.method == 'POST':
        # --- Process POST Request (Save Changes) ---
        title = request.form['title'].strip()
        q_level = request.form['q_level'].upper()
        desc = request.form['description'].strip()
        test_cases_raw = request.form['test_cases']

        # Validate Time Limit (Minutes)
        try:
            time_limit_minutes = int(request.form.get('time_limit_minutes', 15))
            if not (1 <= time_limit_minutes <= 15):
                flash("F!L Time Limit (Minutes) must be between 1 and 15 minutes.", "error")
                return redirect(url_for('admin_edit_question', qid=qid))
        except ValueError:
            flash("F!L Time Limit (Minutes) must be a valid number.", "error")
            return redirect(url_for('admin_edit_question', qid=qid))

        # Validate Runtime Limit (Seconds)
        try:
            runtime_limit_seconds = float(request.form.get('runtime_limit_seconds', 2.0))
            if not (0.1 <= runtime_limit_seconds <= 10.0):
                flash("F!L Runtime Limit (Seconds) must be between 0.1 and 10.0 seconds.", "error")
                return redirect(url_for('admin_edit_question', qid=qid))
        except ValueError:
            flash("F!L Runtime Limit (Seconds) must be a valid number.", "error")
            return redirect(url_for('admin_edit_question', qid=qid))

        memory_limit_mb = int(request.form.get('memory_limit_mb', 256))

        if not title or not desc or q_level not in LEVELS:
            flash("F!L Title, Description, and Level are required.", "error")
            return redirect(url_for('admin_edit_question', qid=qid))

        # Process and validate new test cases format
        test_cases_list = []
        lines = test_cases_raw.strip().split('\n')
        for i, line in enumerate(lines):
            line = line.strip()
            if not line: continue
            parts = line.split('###', 1)
            if len(parts) == 2:
                test_cases_list.append({"input": parts[0].strip(), "expected_output": parts[1].strip()})
            else:
                flash(f"F!L Error in Test Case line {i + 1}: Must be 'Input###ExpectedOutput'", "error")
                return redirect(url_for('admin_edit_question', qid=qid))

        if not test_cases_list:
            flash("F!L At least one valid test case is required.", "error")
            return redirect(url_for('admin_edit_question', qid=qid))

        # Update the question dictionary
        q['title'] = title
        q['level'] = q_level
        q['description'] = desc
        q['time_limit_minutes'] = time_limit_minutes
        q['runtime_limit_seconds'] = runtime_limit_seconds
        q['memory_limit_mb'] = memory_limit_mb
        q['test_cases'] = test_cases_list

        save_questions(qdict)
        flash(f"✔️ Problem {qid} updated.", "success")
        return redirect(url_for('admin_dashboard'))

    # GET Request
    current_level = q.get('level', 'A')
    current_time_limit = q.get('time_limit_minutes', 15)
    current_runtime_limit = q.get('runtime_limit_seconds', 2.0)
    current_memory_limit = q.get('memory_limit_mb', 256)

    content = f"""
    <div class="card">
        <h3>// EDIT PROBLEM {qid}: {q.get('title', 'Untitled')} //</h3>
        <form method="POST" action="{url_for('admin_edit_question', qid=qid)}">

            <div class="form-group">
                <label>PROBLEM TITLE</label>
                <input name="title" value="{q.get('title', '')}" required>
            </div>

            <div class="grid-4">
                <div class="form-group">
                    <label>LEVEL</label>
                    <select name="q_level" required>
                        {
    ''.join(f'<option value="{level}" class="level-{level}" {"selected" if level == current_level else ""}>{level}</option>' for level in LEVELS)
    }
                    </select>
                </div>
                <div class="form-group">
                    <label>TIME LIMIT (MIN)</label>
                    <input name="time_limit_minutes" type="number" min="1" max="15" value="{current_time_limit}" required>
                </div>
                <div class="form-group">
                    <label>RUNTIME (S) [0.1-10]</label>
                    <input name="runtime_limit_seconds" type="number" step="0.1" min="0.1" max="10" value="{current_runtime_limit}" required>
                </div>
                <div class="form-group">
                    <label>MEMORY (MB)</label>
                    <input name="memory_limit_mb" type="number" min="128" max="512" value="{current_memory_limit}" required>
                </div>
            </div>

            <div class="form-group">
                <label>DESCRIPTION (Use $A^B$ for math)</label>
                <textarea name="description" rows="5" required>{q.get('description', '')}</textarea>
            </div>

            <div class="form-group">
                <label>TEST CASES (Input###ExpectedOutput, one per line)</label>
                <textarea name="test_cases" rows="8" required>{current_test_cases_raw}</textarea>
            </div>

            <button type="submit" class="btn-primary" style="width:100%;">SAVE PROBLEM</button>
        </form>
    </div>
    """
    return render_base(content)


@app.route('/admin/delete_user/<username>')
def admin_delete_user(username):
    """Deletes a user account."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    users = load_users()
    if username in users:
        if username == ADMIN_USER:
            flash("F!L Cannot delete the main administrator account", "error")
            return redirect(url_for('admin_dashboard'))

        users.pop(username)
        save_users(users)
        flash(f"✔️ User {username} deleted", "success")
        logger.info(f"Admin {session.get('username')} deleted user: {username}")
    else:
        flash("F!L User not found", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_question/<int:qid>')
def admin_delete_question(qid):
    """Deletes a question by ID."""
    if session.get('role') != 'admin':
        flash("F!L Admin credentials required", "error")
        return redirect(url_for('login_page'))

    qdict = load_questions()
    qid_str = str(qid)
    if qid_str in qdict:
        question_title = qdict[qid_str].get('title', f'Question {qid}')
        qdict.pop(qid_str)
        save_questions(qdict)
        flash("✔️ Problem deleted", "success")
        logger.info(f"Admin {session.get('username')} deleted question: {question_title}")
    else:
        flash("F!L Problem not found", "error")
    return redirect(url_for('admin_dashboard'))


@app.route('/')
def index():
    """Redirects authenticated users to the appropriate dashboard."""
    if session.get('role') == 'user':
        return redirect(url_for('questions_list'))
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('login_page'))


@app.route('/questions')
def questions_list():
    """
    Displays the list of questions filtered and grouped by the user's level (like a CP sheet).
    """
    if session.get('role') != 'user':
        flash("F!L Login required", "error")
        return redirect(url_for('login_page'))

    username = session.get('username')

    user_level = session.get('user_level', 'A').upper()
    user_level_rank = LEVEL_MAP.get(user_level, 0)

    qdict = load_questions()
    all_qs = [qdict[k] for k in sorted(qdict.keys(), key=lambda x: int(x))]

    # --- Grouping Logic: Dictionary where keys are levels ('A', 'B', ...) ---
    grouped_questions = {level: [] for level in LEVELS if LEVEL_MAP.get(level) <= user_level_rank}

    total_questions_shown = 0
    for q in all_qs:
        q_level = q.get('level', 'A').upper()
        q_level_rank = LEVEL_MAP.get(q_level, 0)

        # Filter 1: Only show questions <= user's level rank
        if q_level_rank <= user_level_rank:
            q['status'] = get_user_status_for_question(username, str(q['id']))

            if q_level in grouped_questions:
                grouped_questions[q_level].append(q)
                total_questions_shown += 1

    # Get ordered list of levels to display (A, B, C...)
    ordered_levels_to_show = [level for level in LEVELS if level in grouped_questions]

    # Check contest status for display/filtering links
    status, message = check_contest_status()
    is_contest_active = status == "ACTIVE"

    inner_content = f"""
  <div class="card">
    <h3>// PROBLEM ARCHIVE // (User LVL: <span class="level-{{session.user_level}}">{{session.user_level}}</span>)</h3>
    <div class="card contest-{status.lower()}" style="margin-bottom: 20px;">
        STATUS: <strong>{status}</strong> | {message}
        {'{% if not is_contest_active and status != "OFFLINE" %}'}
            <p class="small" style="color:#fff;">[ Mode: Training. Submissions only count during active Contests ]</p>
        {'{% endif %}'}
    </div>

    {'{% if total_questions_shown > 0 %}'}

    {'{% for level in ordered_levels_to_show %}'}
        {'{% if grouped_questions[level]|length > 0 %}'}
            <h4 class="level-{{{{ level }}}}">// LEVEL {{{{ level }}}} PROBLEMS ({{{{ grouped_questions[level]|length }}}} ENTRIES) //</h4>
            <table>
                <tr><th>ID</th><th>LEVEL</th><th>TITLE</th><th>TIME (MIN)</th><th>RUN (S)</th><th>MEM (MB)</th><th>STATUS</th><th>LINK</th></tr>
                {'{% for q in grouped_questions[level] %}'}
                <tr>
                    <td><strong>{{{{ q.id }}}}</strong></td>
                    <td class="level-{{{{ q.get('level', 'A') }}}}"><strong>{{{{ q.get('level', 'A') }}}}</strong></td>
                    <td>{{{{ q.title }}}}</td>
                    <td>{{{{ q.get('time_limit_minutes', 15) }}}}</td>
                    <td class="runtime-{{{{ 'slow' if q.get('runtime_limit_seconds', 2.0) > 3.0 else 'good' }}}}">{{{{ q.get('runtime_limit_seconds', 2.0) }}}}</td>
                    <td>{{{{ q.get('memory_limit_mb', 256) }}}}</td>
                    <td>
                        <span class="status-{{{{ q.status.split(' ')[0] }}}}">
                            {{{{ '✔️ ACCEPTED' if q.status == 'Accepted' else '🚨 CHEATED' if q.status == 'Cheated' else q.status | upper | replace('ANSWER', 'ANS') | replace('NOT', '---') | replace('ATTEMPTED', '---') }}}}
                        </span>
                    </td>
                    <td>
                        <a href="{{{{ url_for('user_question', qid=q.id) }}}}">
                            <button class="btn-primary">ACCESS</button>
                        </a>
                    </td>
                </tr>
                {'{% endfor %}'}
            </table>
            <br>
        {'{% endif %}'}
    {'{% endfor %}'}

    {'{% else %}'}
    <p style="color:#a0a0a0; text-align:center;">No problems available for your current level ({{session.user_level}})</p>
    {'{% endif %}'}
  </div>
"""
    rendered_content = render_template_string(
        inner_content,
        grouped_questions=grouped_questions,
        ordered_levels_to_show=ordered_levels_to_show,
        total_questions_shown=total_questions_shown,
        session=session,
        is_contest_active=is_contest_active,
        status=status,
        message=message
    )
    return render_base(rendered_content)


@app.route('/question/<int:qid>', methods=['GET', 'POST'])
def user_question(qid):
    """
    Displays a single question, handles code submission via API,
    and manages the per-question timer and AI cheating detection.
    """
    if session.get('role') != 'user':
        flash("F!L Login required", "error")
        return redirect(url_for('login_page'))

    qdict = load_questions()
    q = qdict.get(str(qid))

    if not q:
        flash("F!L Problem not found", "error")
        return redirect(url_for('questions_list'))

    user_level_rank = LEVEL_MAP.get(session.get('user_level', 'A'), 0)
    q_level_rank = LEVEL_MAP.get(q.get('level', 'A'), 0)

    if q_level_rank > user_level_rank:
        flash(f"F!L This is a Level {q.get('level')} problem, above your current clearance.", "error")
        return redirect(url_for('questions_list'))

    # --- TIMER LOGIC ---
    timer_key = f'q_start_{qid}'
    TIME_LIMIT_MINUTES = q.get('time_limit_minutes', 15)
    
    if timer_key not in session:
        start_dt = datetime.now(timezone.utc)
        session[timer_key] = start_dt.strftime('%Y-%m-%d %H:%M:%S')
    else:
        start_dt = datetime.strptime(session[timer_key], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)

    end_dt = start_dt + timedelta(minutes=TIME_LIMIT_MINUTES)
    time_remaining_seconds = max(0, int((end_dt - datetime.now(timezone.utc)).total_seconds()))
    is_time_expired = time_remaining_seconds == 0

    status, message = check_contest_status()
    is_contest_active = status == "ACTIVE"
    is_submission_allowed = is_contest_active and not is_time_expired

    if is_time_expired:
        timer_status_message = "F!L Time Limit Reached"
    else:
        timer_status_message = f"Time Remaining: <span id='countdown'></span> ({TIME_LIMIT_MINUTES} min limit)"
        
    RUNTIME_LIMIT = q.get('runtime_limit_seconds', DEFAULT_RUNTIME_LIMIT_SECONDS)
    # --- END TIMER LOGIC ---

    overall_result = None
    compile_error = None
    test_case_results = []

    default_code = """// Write your C++ code here
#include <iostream>
#include <string>

using namespace std;

int main() {
    // Read your inputs (e.g., int A, B;)
    // Process them
    // Print your final result to standard output (cout << result << endl;)

    // Example: Read two integers and print their sum
    int A, B;
    if (!(cin >> A >> B)) return 1; 
    cout << A + B << endl;

    return 0;
}"""

    code_to_display = request.form.get('code', default_code)

    if request.method == 'POST':
        if not is_submission_allowed:
            flash("F!L Submission is currently disabled (Contest is not ACTIVE or time expired).", "error")
            return redirect(url_for('user_question', qid=qid))

        # --- Submission Logic (Code Execution and Grading via API) ---
        code = request.form['code']
        username = session['username']
        current_overall_status = "Accepted"
        
        try:
            test_cases = q.get('test_cases', [])

            for i, test_case in enumerate(test_cases):
                input_data = test_case.get('input', '')
                expected_output = test_case.get('expected_output', '').strip()
                test_result = {'status': 'Pending', 'output': None, 'input': input_data,
                               'expected': expected_output, 'runtime': 0.0}

                # 1. Execute code via external API
                api_status, actual_output, runtime = run_code_via_api(
                    code, 
                    input_data, 
                    RUNTIME_LIMIT
                )

                test_result['runtime'] = runtime
                actual_output = actual_output.strip()

                if api_status != "Accepted":
                    test_result['status'] = api_status
                    current_overall_status = api_status
                    if overall_result is None: overall_result = f"{api_status} on Test Case {i + 1}"
                
                elif actual_output == expected_output:
                    test_result['status'] = "Accepted"
                else:
                    test_result['status'] = "Wrong Answer"
                    if current_overall_status == "Accepted":
                        current_overall_status = "Wrong Answer"
                        overall_result = f"Wrong Answer on Test Case {i + 1}"

                test_result['output'] = actual_output
                
                test_case_results.append(test_result)
                if current_overall_status != "Accepted": 
                    if current_overall_status == "Compile Error":
                        compile_error = actual_output # Use output for compiler errors
                    break # Stop on first failure

            # 2. Final Result and User Record Update
            users = load_users()
            user_data = users.get(username)
            qid_str = str(qid)
            
            # Ensure submission record exists
            if 'submissions' not in user_data: user_data['submissions'] = {}
            if qid_str not in user_data['submissions']: user_data['submissions'][qid_str] = {
                'best_status': 'Not Attempted', 'attempts': 0, 'ai_flagged': False, 'ai_reason': ''}
            
            sub_info = user_data['submissions'][qid_str]
            sub_info['attempts'] += 1

            is_best_ac_or_cheated = sub_info['best_status'] in ['Accepted', 'Cheated'] 
            
            if current_overall_status == "Accepted":
                
                # --- ENHANCED AI CHEATING DETECTION ---
                ai_flagged, ai_reason = enhanced_ai_detection(code, q.get('description', ''))

                if ai_flagged:
                    # Log the cheat but tell the user it was AC
                    sub_info['ai_flagged'] = True
                    sub_info['ai_reason'] = ai_reason
                    sub_info['best_status'] = 'Cheated' # Set status for admin view
                    
                    overall_result = "Accepted" # Keep AC status for user display
                    flash("✔️ ACCESS GRANTED. All test cases passed.", "success")
                    logger.info(f"AI cheating detected for user {username} on problem {qid}: {ai_reason}")
                
                elif not is_best_ac_or_cheated:
                    # First real AC (or overwriting a cheated status with a real one)
                    sub_info['ai_flagged'] = False
                    sub_info['ai_reason'] = ""
                    sub_info['best_status'] = 'Accepted'
                    
                    grant_badge(username, "Problem Solved")
                         
                    overall_result = "Accepted"
                    flash("✔️ ACCESS GRANTED. All test cases passed.", "success")
                
                else:
                    # Subsequent AC submissions
                    overall_result = "Accepted"
                    flash("✔️ ACCESS GRANTED. All test cases passed.", "success")


            # Handle non-AC statuses
            elif current_overall_status != "Accepted":
                if overall_result is None:
                    overall_result = f"F!L Submission Failed: {current_overall_status}"
                    flash(f"F!L Submission Failed: {current_overall_status}", "error")
                
                # Update best status only if current status is better than Not Attempted/Compile Error
                if not is_best_ac_or_cheated and sub_info['best_status'] in ['Not Attempted', 'Compile Error']:
                    sub_info['best_status'] = current_overall_status
                
            save_users(users)
            
        except Exception as e:
            logger.error(f"Submission processing failed: {e}")
            flash("F!L An unexpected system error occurred during grading.", "error")
            overall_result = "System Error"
            
        # --- End Submission Logic ---

    # --- HTML Rendering for User Question Page ---
    inner_content = f"""
    <div class="card">
      <header style="display:flex; justify-content:space-between; align-items:center;">
          <h3>// PROBLEM {q['id']} ({q.get('level', 'A')}) // {q['title'].upper()}</h3>
          <div class="card contest-{{'active' if is_submission_allowed else 'finished'}}" style="padding: 10px; margin: 0; min-width: 250px; text-align: center;">
              {timer_status_message}
          </div>
      </header>

      <div class="ai-notice card" style="border-left: 4px solid var(--color-accent);">
          <strong>[ WARNING: AI INTERVENTION PROTOCOL ACTIVE ]</strong>
          <p class="small" style="color:var(--color-text); margin-top: 5px;">Your code will be analyzed for external generation patterns. Unauthorized assistance may result in account termination. Proceed with integrity.</p>
      </div>

      <p style="background:#1a2b4d; padding:15px; border-left:4px solid var(--color-border);">
        {q['description']}
      </p>

      <div class="grid-4" style="font-size:14px; color:#a0a0a0; margin-bottom: 20px;">
          <div><strong style="color:var(--color-accent);">CODING TIME:</strong> {q.get('time_limit_minutes', 15)} MIN</div>
          <div class="runtime-{{'slow' if RUNTIME_LIMIT > 3.0 else 'good'}}">
              <strong style="color:var(--color-accent);">RUN LIMIT:</strong> {RUNTIME_LIMIT} S
          </div>
          <div><strong style="color:var(--color-accent);">MEM LIMIT:</strong> {q.get('memory_limit_mb', 256)} MB</div>
          <div><a href="{{{{ url_for('questions_list') }}}}">← BACK TO ARCHIVE</a></div>
      </div>
      
      <h4>// INPUT CODE //</h4>
      <form method="POST" action="{{{{ url_for('user_question', qid=q.id) }}}}">
        <textarea id="code" name="code">{{{{ code_to_display }}}}</textarea> 
        <br><br>
        <button type="submit" {'disabled' if not is_submission_allowed else ''}>
            {{{{ '► SUBMIT CODE' if is_submission_allowed else '► ACCESS DENIED' }}}}
        </button>
      </form>

      {'{% if not is_submission_allowed and status != "OFFLINE" %}'}
          <p class="small flash-error" style="margin-top:15px; text-align:center;">SUBMISSION LOCKOUT: Contest is not ACTIVE OR Time Expired.</p>
      {'{% endif %}'}

      {'{% if compile_error %}'}
        <h4 style="color: #ff4444;">F!L COMPILATION FAILURE</h4>
        <pre style="border-color:#ff4444; color: #ff8888;">{{{{ compile_error }}}}</pre> 
      {'{% endif %}'}

      {'{% if overall_result %}'}
        <h4>// JUDGEMENT REPORT //</h4>
        {'{% if overall_result == "Accepted" %}'}
          <p class="accepted result-icon-AC"><span class="result-icon">✔️</span> {{{{ overall_result | upper }}}} (CASES PASSED: {{{{ q.get('test_cases', [])|length }}}} / {{{{ q.get('test_cases', [])|length }}}} )</p>
        {'{% else %}'}
          <p class="wrong result-icon-FAIL"><span class="result-icon">F!L</span> {{{{ overall_result | upper }}}}</p>

          {'{% set first_failure = False %}'}
          {'{% for tc in test_case_results %}'}
              {'{% if tc.status != "Accepted" and not first_failure %}'}
                  {'{% set first_failure = True %}'}
                  <h4 style="color: #ff4444;">F!L FAILED TEST CASE: {{{{ tc.status | upper }}}}</h4>
                  <div class="grid-3">
                      <div><label style="color: var(--color-accent);">INPUT VECTOR:</label><pre>{{{{ tc.input }}}}</pre></div>
                      <div><label style="color: #ff4444;">YOUR OUTPUT:</label><pre style="border-color:#ff4444; color: #ff8888;">{{{{ tc.output }}}}</pre></div>
                      <div><label style="color: var(--color-main);">EXPECTED OUTPUT:</label><pre>{{{{ tc.expected }}}}</pre></div>
                  </div>
                  <p class="small" style="color:#fcd34d;">TERMINATING EXECUTION: JUDGE HALTED ON FIRST FAILURE.</p>
              {'{% endif %}'}
          {'{% endfor %}'}
        {'{% endif %}'}
      {'{% endif %}'}
    </div>

    <script>
      // --- CodeMirror Initialization ---
      var editor = CodeMirror.fromTextArea(document.getElementById("code"), {{
        lineNumbers: true,
        mode: "text/x-c++src",
        autoCloseBrackets: true,
        theme: "monokai", 
        readOnly: {{{{ 'true' if not is_submission_allowed else 'false' }}}}
      }});
      editor.setValue(document.getElementById("code").value.trim()); 

      // --- New Countdown Timer Script (HH:MM:SS format) ---
      var timeRemaining = {time_remaining_seconds};
      var countdownElement = document.getElementById('countdown');
      var submitButton = document.querySelector('button[type="submit"]');

      function formatTime(totalSeconds) {{
          var hours = Math.floor(totalSeconds / 3600);
          var minutes = Math.floor((totalSeconds % 3600) / 60);
          var seconds = totalSeconds % 60;

          var parts = [];
          if (hours > 0) parts.push((hours < 10 ? '0' + hours : hours));

          parts.push(minutes < 10 ? '0' + minutes : minutes);
          parts.push(seconds < 10 ? '0' + seconds : seconds);

          return parts.join(':');
      }}

      function updateTimer() {{
          if (timeRemaining <= 0) {{
              timeRemaining = 0;
              countdownElement.innerHTML = 'TIME OUT';
              if (submitButton) {{
                  submitButton.disabled = true;
                  submitButton.innerHTML = '► ACCESS DENIED';
              }}
              clearInterval(timerInterval);
              return;
          }}

          countdownElement.innerHTML = formatTime(timeRemaining);
          timeRemaining--;
      }}

      if (countdownElement) {{
          updateTimer(); 
          var timerInterval = setInterval(updateTimer, 1000);
      }}

    </script>
"""

    rendered_content = render_template_string(
        inner_content,
        q=q,
        overall_result=overall_result,
        compile_error=compile_error,
        code_to_display=code_to_display,
        test_case_results=test_case_results,
        is_submission_allowed=is_submission_allowed,
        status=status,
        message=message,
        RUNTIME_LIMIT=RUNTIME_LIMIT,
        TIME_LIMIT_MINUTES=TIME_LIMIT_MINUTES,
        time_remaining_seconds=time_remaining_seconds
    )
    return render_base(rendered_content)


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Starting Mini Codeforces on port {port}")
    
    from waitress import serve
    serve(app, host='0.0.0.0', port=port)
