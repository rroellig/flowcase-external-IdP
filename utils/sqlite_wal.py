from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy import event
from sqlalchemy.engine import Engine

class SQLiteDialect_pysqlite_wal(SQLiteDialect_pysqlite):
    name = "sqlite+pysqlite_wal"

    @classmethod
    def dbapi(cls):
        import sqlite3
        return sqlite3

# Register WAL mode for all SQLite connections
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, dbapi_connection.__class__):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()