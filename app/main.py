from flask import Flask, request, jsonify, render_template, g
import sqlite3
import psycopg2
import pymysql
import bcrypt
from contextlib import closing

app = Flask(__name__)

# ---------------------------
# Database configuration
# ---------------------------
SQLITE_PATH = "database.db"

POSTGRES_CFG = {
    "dbname": "postgres",
    "user": "postgres",
    "password": "postgres",
    "host": "postgres",
    "port": 5432,
    "client_encoding": "UTF8",
}

MYSQL_CFG = {
    "host": "mysql",
    "user": "root",
    "password": "root",
    "db": "test",
    "port": 3306,
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}

# ---------------------------
# Connection helpers
# ---------------------------

def _sqlite_conn():
    if not hasattr(g, "_sqlite"):
        conn = sqlite3.connect(SQLITE_PATH)
        conn.row_factory = sqlite3.Row
        g._sqlite = conn
    return g._sqlite


def _pg_conn():
    if not hasattr(g, "_pg"):
       g._pg = psycopg2.connect(**POSTGRES_CFG)
    return g._pg


def _mysql_conn():
    if not hasattr(g, "_mysql"):
        g._mysql = pymysql.connect(**MYSQL_CFG)
    return g._mysql


DB_HANDLERS = {
    "sqlite": _sqlite_conn,
#    "postgres": _pg_conn,
    "mysql": _mysql_conn,
}


def db(name: str):
    try:
        return DB_HANDLERS[name]()
    except KeyError:
        raise ValueError(f"Unsupported database: {name}") from None


# ---------------------------
# Schema management
# ---------------------------

def ensure_schema():
    ddl = {
        "sqlite": """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            );
        """,
#        "postgres": """
#            CREATE TABLE IF NOT EXISTS users (
#               id SERIAL PRIMARY KEY,
#                login TEXT UNIQUE NOT NULL,
#               password TEXT NOT NULL
#           );
#        """,
        "mysql": """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                login VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            ) ENGINE=InnoDB;
        """,
    }

    for name, ddl_query in ddl.items():
        connection = db(name)
        with closing(connection.cursor()) as cur:
            cur.execute(ddl_query)
        connection.commit()


@app.teardown_appcontext
def _close_connections(_):
    for attr in ("_sqlite", "_pg", "_mysql"):
        if hasattr(g, attr):
            getattr(g, attr).close()


# ---------------------------
# Helper utilities
# ---------------------------

def _password_hash(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def _password_matches(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ---------------------------
# Views
# ---------------------------

@app.route("/")
def index():
    return render_template("home.html")


# ----- Authorization -----
@app.route("/authorization", methods=["GET", "POST"])
def authorization():
    if request.method == "POST":
        login = request.form.get("Login")
        passwd = request.form.get("Password")
        backend = request.form.get("db", "sqlite")

        
        backends = [backend] if backend != "all" else DB_HANDLERS.keys()
        for name in backends:
            conn = db(name)
            cur = conn.cursor()
            placeholder = "%s" if name != "sqlite" else "?"
            cur.execute(f"SELECT password FROM users WHERE login = {placeholder}", (login,))
            row = cur.fetchone()
            if row and _password_matches(passwd, row[0]):
                return render_template("successfulauth.html")

        return render_template("auth_bad.html")

    return render_template("authorization.html")


# ----- Registration -----
@app.route("/registration", methods=["GET", "POST"])
def registration():
    if request.method == "POST":
        login = request.form.get("Login")
        passwd = request.form.get("Password")
        hashed = _password_hash(passwd)

        
        for name in DB_HANDLERS.keys():
            conn = db(name)
            cur = conn.cursor()
            placeholder = "%s" if name != "sqlite" else "?"
            cur.execute(f"SELECT 1 FROM users WHERE login = {placeholder}", (login,))
            if cur.fetchone():
                return render_template("registration_error.html", message="Пользователь с таким логином уже существует.")

      
        for name in DB_HANDLERS.keys():
            conn = db(name)
            cur = conn.cursor()
            placeholder = "%s" if name != "sqlite" else "?"
            cur.execute(f"INSERT INTO users (login, password) VALUES ({placeholder}, {placeholder})", (login, hashed))
            conn.commit()

        return render_template("successfulregis.html")

    return render_template("registration.html")


# ---------------------------
# REST API
# ---------------------------

@app.route("/api/users", methods=["GET"])
def api_get_users():
    backend = request.args.get("db", "sqlite")
    users = []

    targets = [backend] if backend != "all" else DB_HANDLERS.keys()
    for name in targets:
        conn = db(name)
        cur = conn.cursor()
        cur.execute("SELECT login FROM users")
        users.extend([row[0] if isinstance(row, (list, tuple)) else row["login"] for row in cur.fetchall()])

    return jsonify(users)


@app.route("/api/users/<login>", methods=["GET"])
def api_get_user(login):
    backend = request.args.get("db", "sqlite")
    targets = [backend] if backend != "all" else DB_HANDLERS.keys()

    for name in targets:
        conn = db(name)
        cur = conn.cursor()
        placeholder = "%s" if name != "sqlite" else "?"
        cur.execute(f"SELECT login FROM users WHERE login = {placeholder}", (login,))
        row = cur.fetchone()
        if row:
            login_value = row[0] if isinstance(row, (list, tuple)) else row["login"]
            return jsonify({"login": login_value})

    return jsonify({"error": "User not found"}), 404


@app.route("/api/users", methods=["POST"])
def api_create_user():
    data = request.get_json(force=True)
    login = data.get("login")
    passwd = data.get("password")

    if not login or not passwd:
        return jsonify({"error": "Wrong credentials"}), 400

    hashed = _password_hash(passwd)

    try:
        for name in DB_HANDLERS.keys():
            conn = db(name)
            cur = conn.cursor()
            placeholder = "%s" if name != "sqlite" else "?"
            cur.execute(f"INSERT INTO users (login, password) VALUES ({placeholder}, {placeholder})", (login, hashed))
            conn.commit()
        return jsonify({"message": "User Created"}), 201
    except Exception as exc:
        
        for name in DB_HANDLERS.keys():
            try:
                db(name).rollback()
            except Exception:
                pass
        return jsonify({"error": str(exc)}), 500


@app.route("/api/users/<login>", methods=["DELETE"])
def api_delete_user(login):
    backend = request.args.get("db", "sqlite")
    targets = [backend] if backend != "all" else DB_HANDLERS.keys()

    for name in targets:
        conn = db(name)
        cur = conn.cursor()
        placeholder = "%s" if name != "sqlite" else "?"
        cur.execute(f"DELETE FROM users WHERE login = {placeholder}", (login,))
        conn.commit()

    return jsonify({"message": "Пользователь удалён"}), 200


# ---------------------------
# Application entry point
# ---------------------------

if __name__ == "__main__":
    with app.app_context():
        ensure_schema()
    app.run(debug=False, host="0.0.0.0", port=5000)
