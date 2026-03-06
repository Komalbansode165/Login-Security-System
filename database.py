import mysql.connector

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root123",   # change if needed
    "database": "loginsecurity"
}

def get_connection():
    try:
        return mysql.connector.connect(**DB_CONFIG)
    except mysql.connector.Error as e:
        print("Database Error:", e)
        return None


def init_db():
    conn = get_connection()
    if conn is None:
        return

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(100),
            ip_address VARCHAR(50),
            timestamp DATETIME,
            success BOOLEAN,
            activity VARCHAR(100),
            score INT,
            alert VARCHAR(10)
        )
    """)

    conn.commit()
    conn.close()