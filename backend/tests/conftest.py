import os
import psycopg
import pytest
from app.main import ensure_users_table_exists

@pytest.fixture(autouse=True)
def clean_users_table():
    ensure_users_table_exists()   # ✅ 关键一行

    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set")

    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE users RESTART IDENTITY;")