from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import bcrypt
import os
import jwt
import datetime

app = Flask(__name__)
CORS(app)

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "eventrent-secret-2026")

def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    return sqlite3.connect(DB_FILE)

@app.route("/")
def index():
    return "EventRent API is running!", 200

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ!"})

    conn = get_db()
    existing = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "message": "Tài khoản đã tồn tại!"})

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    conn.execute("INSERT INTO users VALUES (?, ?)", (username, hashed))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Đăng ký thành công!"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    conn = get_db()
    row = conn.execute("SELECT password FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not row or not bcrypt.checkpw(password.encode(), row[0].encode()):
        return jsonify({"success": False, "message": "Tài khoản hoặc mật khẩu không đúng!"})

    token = jwt.encode({
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({
        "success": True,
        "message": f"Chào mừng {username}!",
        "username": username,
        "token": token
    })

@app.route("/verify", methods=["POST"])
def verify():
    data = request.json
    token = data.get("token", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"success": True, "username": payload["username"]})
    except jwt.ExpiredSignatureError:
        return jsonify({"success": False, "message": "Token đã hết hạn!"})
    except Exception:
        return jsonify({"success": False, "message": "Token không hợp lệ!"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000, debug=False)
