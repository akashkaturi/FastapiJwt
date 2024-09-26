from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from uuid import uuid4
from database import get_db, User, BlacklistedToken, is_black_listed, check_blacklist, add_user
from deps import get_current_user, verify_refresh_token
from schemas import UserOut, UserAuth, TokenSchema, MeResponse, LoggedOutMessage, UserLoginForm
from utils import (
    get_hashed_password,
    create_access_token,
    verify_password,
    create_refresh_token,

)
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
    "http://localhost",
    "http://127.0.0.1:3000",
    'http://localhost:8080',
    "http://localhost:3000",

]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/signup", summary="Create new user", response_model=UserOut)
async def create_user(data: UserAuth, db: Session = Depends(get_db)):
    # querying database to check if user already exists
    user = db.query(User).filter(User.email == data.email).first()
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )
    hashed_password = get_hashed_password(data.password)
    new_user = add_user(db=db, email=data.email, password=hashed_password)
    return new_user


@app.post(
    "/login",
    summary="Create access and refresh tokens for user",
    response_model=TokenSchema,
)
async def login(
        form_data: UserLoginForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()
    if user is None or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )
    return {
        "access_token": create_access_token(user),
        "refresh_token": create_refresh_token(user),
    }


@app.post("/refresh", summary="Refresh access token", response_model=TokenSchema)
async def refresh_token(refresh_token: str, db: Session = Depends(get_db)):
    try:
        user_details = verify_refresh_token(refresh_token, db)
        if not user_details:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

        user = db.query(User).filter(User.id == user_details.id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return {
            "access_token": create_access_token(user),
            "refresh_token": create_refresh_token(user),
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not refresh token {e}",
        )


@app.post("/logout", summary="Logout user and blacklist token")
async def logout(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Add the current user's token to the blacklisted_tokens table
    blacklisted_token = BlacklistedToken(token=current_user.token)
    db.add(blacklisted_token)
    db.commit()
    return {"message": "Successfully logged out"}


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/some")
def read_root(current_user: User = Depends(get_current_user)):
    return {"Hello": f"{current_user.email}"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None):
    return {"item_id": item_id, "q": q}


@app.get(
    "/me", summary="Get details of currently logged in user", response_model=MeResponse
)
@check_blacklist
async def get_me(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return current_user
