from sqlalchemy import Column, String
from sqlalchemy.orm import Session
from functools import wraps
from pydantic import EmailStr
from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from schemas import SystemUser, UserSchema
from sqlalchemy import Column, Boolean, Integer, String
from uuid import UUID
import uuid

app = FastAPI()

# SQLAlchemy configuration
SQLALCHEMY_DATABASE_URL = "sqlite:///./user_database.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency to get database session


async def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Define User model

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(
        String(length=36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )
    email = Column(String, unique=True, index=True)
    password = Column(String)


class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    id = Column(
        String(length=36),
        primary_key=True,
        index=True,
        default=lambda: str(uuid.uuid4()),
    )
    token = Column(String, primary_key=True, unique=True)


# Create tables
def create_tables():
    Base.metadata.create_all(bind=engine)


# Functions for CRUD operations
def add_user(db: Session, email: str, password: str):
    try:
        user = UserSchema(email=email, password=password)
        db_user = User(email=user.email, password=user.password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error {e}")


def check_blacklist(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        user = kwargs.get("current_user")
        db = kwargs.get("db")

        # Check if the token is blacklisted
        blacklisted_token = db.query(BlacklistedToken).filter(
            BlacklistedToken.token == user.token).first()
        if blacklisted_token:
            raise HTTPException(
                status_code=401, detail="User Logged Out, Login Again")

        # Call the original function
        return await func(*args, **kwargs)

    return wrapper


def is_black_listed(user: SystemUser, db: Session):
    blacklisted_token = db.query(BlacklistedToken).filter(
        BlacklistedToken.token == user.token).first()
    return True if blacklisted_token else False


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()


# Call create_tables() to create tables when the application starts
create_tables()
