from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
from database import get_connection

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

BLOCKED_IPS = {}

class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/")
def home():
    return FileResponse("static/index.html")


@app.get("/admin")
def admin_page():
    return FileResponse("static/admin.html")


def analyze(ip):
    conn = get_connection()
    if not conn:
        return "NORMAL ACTIVITY", 0, "NO"

    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT success, timestamp FROM login_logs WHERE ip_address=%s",
        (ip,)
    )
    rows = cursor.fetchall()
    conn.close()

    one_minute_ago = datetime.now() - timedelta(minutes=1)
    fails = 0

    for row in rows:
        if row["timestamp"] >= one_minute_ago and row["success"] == 0:
            fails += 1

    if fails >= 5:
        return "BRUTE FORCE ATTACK DETECTED", fails, "YES"
    elif fails >= 3:
        return "SUSPICIOUS ACTIVITY", fails, "YES"
    else:
        return "NORMAL ACTIVITY", fails, "NO"


@app.post("/login")
def login(data: LoginRequest, request: Request):
    ip = request.client.host
    success = 1 if data.password == "12345" else 0

    activity, score, alert = analyze(ip)

    if activity == "BRUTE FORCE ATTACK DETECTED":
        BLOCKED_IPS[ip] = datetime.now()

    conn = get_connection()
    if not conn:
        return {"login_success": False}

    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO login_logs
        (username, ip_address, timestamp, success, activity, score, alert)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        data.username,
        ip,
        datetime.now(),
        success,
        activity,
        score,
        alert
    ))

    conn.commit()
    conn.close()

    return {
        "login_success": bool(success),
        "activity": activity,
        "alert": alert
    }


@app.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT COUNT(*) as total FROM login_logs")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) as success FROM login_logs WHERE success=1")
    success = cursor.fetchone()["success"]

    cursor.execute("SELECT COUNT(*) as failed FROM login_logs WHERE success=0")
    failed = cursor.fetchone()["failed"]

    cursor.execute("SELECT COUNT(*) as attacks FROM login_logs WHERE activity='BRUTE FORCE ATTACK DETECTED'")
    attacks = cursor.fetchone()["attacks"]

    conn.close()

    return {
        "total": total,
        "success": success,
        "failed": failed,
        "attacks": attacks
    }