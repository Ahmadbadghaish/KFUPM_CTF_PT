import sqlite3

def create_database():
    conn = sqlite3.connect('ctf_lab.db')
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    ''')

    # Create files table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_number INTEGER NOT NULL,
        filename TEXT NOT NULL,
        description TEXT
    )
    ''')

    # Insert sample user data
    cursor.executemany('''
    INSERT OR IGNORE INTO users (username, password)
    VALUES (?, ?)
    ''', [
        ('Sean', 'admin123'),
        ('ahmad', 'admin123'),
        ('osama', 'admin123')
    ])  # Replace with hashed password in production.

    # Insert sample files data
    files = [
        (1, 'report1.pdf', 'First report file'),
        (2, 'report2.pdf', 'Second report file')
    ]
    cursor.executemany('INSERT INTO files (file_number, filename, description) VALUES (?, ?, ?)', files)

    conn.commit()
    conn.close()
    print("Database setup completed.")

if __name__ == '__main__':
    create_database()
