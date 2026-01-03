import os
from datetime import datetime, timedelta, timezone

import psycopg
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI app
app = FastAPI()

# Environment variables
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")

# password hashing context, using bcrypt algorithm
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)

# Pydantic model for user registration request
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

# Pydantic model for user login request
class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Pydantic model for token response (JWT/OAuth2)
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Database connection function
def get_db_connection():
    """Establish a connection to the PostgreSQL database."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set in environment variables")
    return psycopg.connect(DATABASE_URL)

# Create users table if it doesn't exist
# close the connection after creating the table
def ensure_users_table_exists():
    """Ensure the users table exists in the database."""
    create_table_query = """
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(create_table_query)
        conn.commit()

# Run the table creation on startup
@app.on_event("startup")
def on_startup():
    """Actions to perform on application startup."""
    ensure_users_table_exists()

# check health endpoint. If the process is running, it is healthy
# If not, according to this endpoint, the porcess will restart
@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "ok"}

@app.get("/db-check")
def db_check():
    """Database connectivity check endpoint."""
    if not DATABASE_URL:
        return {"ok": False, "error": "DATABASE_URL is not set"}
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            row = cur.fetchone()
            if row is None:
                raise RuntimeError("Database did not return any result")
            val = row[0]
    return {"ok": True, "result": val}

# User registration endpoint
@app.post("/auth/register", response_model=TokenResponse)
def register_user(payload: RegisterRequest):
    """Register a new user and return a JWT token."""
    email = payload.email.lower().strip()
    plain_password = payload.password
    if len(plain_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    # Generate password hash keep securely
    password_hash = pwd_context.hash(plain_password)
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Insert new user into the database and return the new user ID
                cur.execute(
                    "INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id;",
                    (email, password_hash),
                )
                row= cur.fetchone()
                if row is None:
                    raise RuntimeError("Failed to insert new user")
                user_id = row[0]
            conn.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Email is already registered")
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    # Create JWT token payload
    token_payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expires_at
    }
    # Create JWT token
    access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALG)

    return TokenResponse(access_token=access_token)

# User login endpoint
@app.post("/auth/login", response_model=TokenResponse)
def login_user(payload: LoginRequest):
    """Authenticate a user and return a JWT token."""
    email = payload.email.lower().strip()
    plain_password = payload.password
    
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # Retrieve user by email
            cur.execute(
                "SELECT id, password_hash FROM users WHERE email = %s;",
                (email,),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    user_id, password_hash = row
    # Verify password
    if not pwd_context.verify(plain_password, password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    # Create JWT token payload
    token_payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expires_at
    }
    # Create JWT token
    access_token = jwt.encode(token_payload, JWT_SECRET, algorithm=JWT_ALG)

    return TokenResponse(access_token=access_token)
                
