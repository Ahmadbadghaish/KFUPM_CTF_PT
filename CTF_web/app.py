from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort, flash, session, render_template_string
from markupsafe import escape
import sqlite3
import os
import subprocess

app = Flask(__name__)
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# In-memory dictionary to store comments for each session
comments_by_session = {}

DATABASE = 'ctf_lab.db'

# Directory settings for each vulnerability
UPLOAD_DIRECTORIES = {
    "command_injection": "flags/command_injection",
    "sqli": "flags/sqli",
    "ssti": "flags/ssti",
    "xss": "flags/xss",
    "uploads": "flags/uploads"
}

# Ensure directories exist
for directory in UPLOAD_DIRECTORIES.values():
    os.makedirs(directory, exist_ok=True)

# Static list of files for IDOR (in a real scenario, this could be in a database)
IDOR_FILES = [
    {"id": 1, "filename": "secret_report1.pdf"},
    {"id": 2, "filename": "secret_report2.pdf"},
    {"id": 3, "filename": "confidential_data3.pdf"}
]

# Helper function for secure path resolution
def secure_filepath(directory, filename):
    base_path = os.path.abspath(directory)
    target_path = os.path.abspath(os.path.join(base_path, filename))
    if not target_path.startswith(base_path):  # Prevent path traversal
        abort(403)
    return target_path

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Home page
@app.route('/')
def index():
    return render_template('index.html')

# Route for robots.txt
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

# Route for robots.txt
@app.route('/names.txt')
def employees_txt():
    return send_from_directory(app.static_folder, 'names.txt')
    
    
# Function to check if input contains `=`
def contains_invalid_characters(input_string):
    return "=" in input_string

# Login page with SQL Injection and SSTI vulnerabilities
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Reject input if it contains `=`
        if contains_invalid_characters(username) or contains_invalid_characters(password):
            flash("Invalid characters in input", "danger")
            return render_template('login.html', comments=comments)
        
        conn = get_db_connection()

        # SQL Injection vulnerability by directly injecting inputs into the query
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()

        if user:
            # Case 3: If both username and password are correct
            session['username'] = username
            flash("Successfully logged in!", "success")
            return redirect(url_for('admin'))
        else:
            # Separate checks for user existence and invalid credentials
            user_check = conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
            if user_check:
                # Case 2: User exists, but password is incorrect
                flash("Invalid credentials", "danger")
            else:
                # Case 1: User does not exist, rendering username with SSTI vulnerability
                # Vulnerable to SSTI by rendering the username directly with render_template_string
                return render_template_string(f"{username} does not exist")

        conn.close()

    # Always pass comments to the template
    # Pass session-specific comments to the template
    session_id = session.get('session_id', None)
    user_comments = comments_by_session.get(session_id, [])
    return render_template('login.html', comments=user_comments)


# Comment submission (XSS vulnerability)
@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    # Ensure each user has a unique session ID
    if 'session_id' not in session:
        session['session_id'] = os.urandom(16).hex()

    session_id = session['session_id']
    comment = request.form['comment']

    # Initialize comment list for this session if not already present
    if session_id not in comments_by_session:
        comments_by_session[session_id] = []

    # Add the comment to the session-specific list
    comments_by_session[session_id].append(comment)

    flash("Comment submitted!", "success")
    return redirect(url_for('login'))
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    flag = "CC6{SQLi_master}"
    command_output = ""

    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()

        # Only allow 'ping' with the hostname to disguise the vulnerability
        cmd = f"ping -c 4 {hostname}"

        try:
            # Execute the command and capture the output
            command_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            flash("Connection test executed successfully", "success")
        except subprocess.CalledProcessError as e:
            command_output = e.output
            flash("Connection test failed", "danger")
    
    return render_template('admin.html', flag=flag, output=command_output)

# Route to display memes with links
@app.route('/files/memes/')
def meme_list():
    conn = get_db_connection()
    memes = conn.execute('SELECT * FROM files ORDER BY id ASC LIMIT 2').fetchall()
    conn.close()

    return render_template('memes.html', memes=memes)



# Route to serve individual meme by ID
@app.route('/files/memes/<int:meme_id>')
def serve_meme(meme_id):
    conn = get_db_connection()
    meme = conn.execute('SELECT * FROM files WHERE id = ?', (meme_id,)).fetchone()
    conn.close()

    if meme:
        return render_template('meme_detail.html', meme=meme)
    else:
        abort(404)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=81, debug=True)
