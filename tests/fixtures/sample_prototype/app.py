"""Sample prototype application used as a test fixture for scanner integration tests.

This file intentionally contains numerous production-readiness gaps that
proto_gap is designed to detect, including hardcoded secrets, debug mode,
SQLite usage, missing error handling, eval(), pickle, and no logging setup.
"""

from flask import Flask, request
import pickle
import hashlib
import subprocess
import logging

# AUTH001: Hardcoded secret key
SECRET_KEY = "hardcoded_secret"

# AUTH001: Hardcoded JWT secret
JWT_SECRET = "jwt_tiny"

# ENV001: Debug mode hardcoded in source
DEBUG = True

# AUTH003: Hardcoded password literal
password = "admin123"

# ENV002: Hardcoded database connection string
DATABASE_URL = "postgresql://user:pass@localhost/mydb"

# MIG003: SQLite database URL
SQLITE_URL = "sqlite:///prototype.db"

app = Flask(__name__)


# AUTH002: Route without authentication middleware
@app.route("/admin")
def admin_panel():
    """Admin panel — no authentication check."""
    return "Admin area"


# AUTH002: FastAPI-style route without auth
@app.route("/users")
def list_users():
    """List all users — publicly accessible."""
    return "User list"


# SEC001: Dynamic code execution via eval()
@app.route("/eval")
def run_eval():
    """Dangerous eval endpoint."""
    cmd = request.args.get("cmd", "")
    result = eval(cmd)  # noqa: S307
    return str(result)


# SEC001: exec() usage
@app.route("/exec")
def run_exec():
    """Dangerous exec endpoint."""
    code = request.args.get("code", "")
    exec(code)  # noqa: S102
    return "done"


# SEC002: subprocess with shell=True
@app.route("/shell")
def run_shell():
    """Shell injection risk."""
    cmd = request.args.get("cmd", "ls")
    output = subprocess.run(cmd, shell=True, capture_output=True)  # noqa: S602
    return output.stdout.decode()


# SEC003: Unsafe pickle deserialization
@app.route("/load", methods=["POST"])
def load_data():
    """Unsafe pickle deserialization from user input."""
    raw = request.get_data()
    obj = pickle.loads(raw)  # noqa: S301
    return str(obj)


# SEC005: Weak MD5 hash
@app.route("/hash")
def hash_password():
    """Hashing a password with broken MD5."""
    pwd = request.args.get("pwd", "")
    hashed = hashlib.md5(pwd.encode()).hexdigest()  # noqa: S324
    return hashed


# SEC005: Weak SHA1 hash
def compute_checksum(data: bytes) -> str:
    """Compute a weak SHA1 checksum."""
    return hashlib.sha1(data).hexdigest()  # noqa: S324


# SEC006: SSL verification disabled
def fetch_external_data(url: str) -> dict:
    """Fetch data from an external URL with SSL verification disabled."""
    import requests
    response = requests.get(url, verify=False)  # noqa: S501
    return response.json()


# ERR001: Bare except clause
def parse_user_input(raw: str) -> int:
    """Parse user input with a bare except clause."""
    try:
        return int(raw)
    except:
        return -1


# ERR002: Silent except with only pass
def safe_divide(a: float, b: float) -> float:
    """Division that silently swallows ZeroDivisionError."""
    try:
        return a / b
    except ZeroDivisionError:
        pass
    return 0.0


# ERR004: Generic Exception raised directly
def validate_age(age: int) -> None:
    """Validate age by raising a generic Exception."""
    if age < 0:
        raise Exception("Age must be non-negative")


# ERR003: Error reported via print() instead of logging
def process_record(record: dict) -> bool:
    """Process a record, reporting errors via print."""
    try:
        value = record["value"]
        return bool(value)
    except KeyError as exc:
        print(f"Error processing record: {exc}")
        return False


# LOG001: print() used instead of structured logging
def start_app() -> None:
    """Start the application using print instead of logging."""
    print("Starting application...")
    print("Connecting to database...")
    print("Application started successfully")


# LOG002: basicConfig used for logging setup
logging.basicConfig(level=logging.DEBUG)


# MIG002: create_all() used instead of migration scripts
def init_database() -> None:
    """Initialize the database using create_all() instead of migrations."""
    from sqlalchemy import create_engine
    from sqlalchemy.ext.declarative import declarative_base

    engine = create_engine(SQLITE_URL)
    Base = declarative_base()
    Base.metadata.create_all(engine)


# MIG004: Destructive SQL statement in source code
DROP_USERS_SQL = "DROP TABLE users"


# AUTH004: Wildcard CORS policy
def configure_cors() -> None:
    """Configure CORS with an overly permissive wildcard policy."""
    # Access-Control-Allow-Origin: *
    pass


if __name__ == "__main__":
    start_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
