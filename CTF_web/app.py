from flask import Flask, render_template, request, redirect, url_for, send_from_directory, abort, flash, session, render_template_string
from markupsafe import escape
import sqlite3
import os
import subprocess

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'ctf_lab.db'
comments = []  # Temporary storage for comments

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
@app.route('/employees.txt')
def employees_txt():
    return send_from_directory(app.static_folder, 'employees.txt')
    
    
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
    return render_template('login.html', comments=comments)



# Comment submission (XSS vulnerability)
@app.route('/submit_comment', methods=['POST'])
def submit_comment():
    comment = request.form['comment']
    comments.append(comment)  # Add comment to the in-memory list
    flash("Comment submitted!", "success")
    return redirect(url_for('login'))  # Redirect back to /login to display comments


# Admin page with Command Injection vulnerability
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'username' not in session:
        return redirect(url_for('login'))

    flag = "CC{Wow_SQLi???}"
    command_output = ""
    if request.method == 'POST':
        cmd = request.form['command']
        try:
            command_output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
            flash("Command executed successfully", "success")
        except subprocess.CalledProcessError as e:
            command_output = e.output
            flash("Command execution failed", "danger")
    return render_template('admin.html', flag=flag, output=command_output)

# Route to serve files specific to SQL Injection
@app.route('/files/uploads/sqli/<filename>')
def serve_sqli_file(filename):
    path = secure_filepath(UPLOAD_DIRECTORIES["sqli"], filename)
    try:
        return send_from_directory(UPLOAD_DIRECTORIES["sqli"], filename)
    except FileNotFoundError:
        abort(404)

# Route to serve files specific to Command Injection
@app.route('/files/uploads/command_injection/<filename>')
def serve_command_injection_file(filename):
    path = secure_filepath(UPLOAD_DIRECTORIES["command_injection"], filename)
    try:
        return send_from_directory(UPLOAD_DIRECTORIES["command_injection"], filename)
    except FileNotFoundError:
        abort(404)

# Route to serve files specific to SSTI
@app.route('/files/uploads/ssti/<filename>')
def serve_ssti_file(filename):
    path = secure_filepath(UPLOAD_DIRECTORIES["ssti"], filename)
    try:
        return send_from_directory(UPLOAD_DIRECTORIES["ssti"], filename)
    except FileNotFoundError:
        abort(404)

# Route to serve files specific to XSS
@app.route('/files/uploads/xss/<filename>')
def serve_xss_file(filename):
    path = secure_filepath(UPLOAD_DIRECTORIES["xss"], filename)
    try:
        return send_from_directory(UPLOAD_DIRECTORIES["xss"], filename)
    except FileNotFoundError:
        abort(404)

# IDOR Vulnerability - List files and access files by ID
@app.route('/files/uploads/')
def idor_file_list():
    flag = "CC{sometimes_you_have_to_look_deeper}"
    return render_template('uploads.html', flag=flag, files=IDOR_FILES)

@app.route('/files/uploads/<int:file_number>')
def serve_upload(file_number):
    # Locate the file entry by ID
    file_entry = next((f for f in IDOR_FILES if f["id"] == file_number), None)
    if file_entry:
        path = secure_filepath(UPLOAD_DIRECTORIES["uploads"], file_entry["filename"])
        try:
            return send_from_directory(UPLOAD_DIRECTORIES["uploads"], file_entry["filename"])
        except FileNotFoundError:
            abort(404)
    else:
        abort(404)

# General file upload route
@app.route('/upload', methods=['POST'])
def file_upload():
    if 'file' not in request.files:
        flash("No file selected", "danger")
        return redirect(url_for('uploads'))
    
    file = request.files['file']
    if file.filename != '':
        file_path = secure_filepath(UPLOAD_DIRECTORIES["uploads"], file.filename)  # Example usage of command_injection directory for uploads
        file.save(file_path)
        flash("File uploaded successfully", "success")
    else:
        flash("Invalid file", "danger")
    return redirect(url_for('uploads'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
