"""
WatchTower SIEM - Database Setup
=================================
Creates the SQLite database engine and session factory.
In production, swap the DATABASE_URL for PostgreSQL.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite for easy local setup. Change to:
# postgresql://user:password@localhost/watchtower   for production
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./watchtower.db")

# connect_args only needed for SQLite (allows multi-threaded access)
connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
