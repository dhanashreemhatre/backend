from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select
from models import Chat, ChatSession,User
from schemas import ChatCreate, ChatResponse, ChatSessionCreate, ChatSessionResponse,UserCreate,Token
from database import get_db
from openai_helper import generate_ai_response
from typing import List
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer
from datetime import datetime, timedelta

router = APIRouter()

# Change these in production
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.exec(select(User).where(User.username == username)).first()
    if user is None:
        raise credentials_exception
    return user

# Add these routes to your routes.py
@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.exec(select(User).where(User.username == user.username)).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = User.get_password_hash(user.password)
    db_user = User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    return {"message": "User created successfully"}

@router.post("/login", response_model=Token)
def login(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.exec(select(User).where(User.username == user.username)).first()
    if not db_user or not db_user.verify_password(user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/session", response_model=ChatSessionResponse)
def create_session(session: ChatSessionCreate, db: Session = Depends(get_db)):
    new_session = ChatSession(title=session.title)
    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session


@router.get("/sessions", response_model=list[ChatSessionResponse])
def list_sessions(db: Session = Depends(get_db)):
    sessions = db.exec(select(ChatSession)).all()
    return sessions

@router.post("/session/{session_id}/chat", response_model=list[ChatResponse])
def create_chat_in_session(session_id: int, chat: ChatCreate, db: Session = Depends(get_db)):
    session = db.get(ChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Retrieve all previous messages for context
    existing_chats = db.exec(select(Chat).where(Chat.session_id == session_id).order_by(Chat.created_at)).all()
    conversation = [{"role": chat.role, "content": chat.content} for chat in existing_chats]

    # Add user's message to the conversation
    user_message = Chat(content=chat.content, role="user", session_id=session_id)
    db.add(user_message)
    db.commit()
    db.refresh(user_message)
    conversation.append({"role": "user", "content": chat.content})

    # Generate AI response
    ai_response_content = generate_ai_response(conversation)
    ai_message = Chat(content=ai_response_content, role="ai", session_id=session_id)
    db.add(ai_message)
    db.commit()
    db.refresh(ai_message)

    return [user_message, ai_message]

@router.get("/session/{session_id}/chats", response_model=list[ChatResponse])
def get_chats_in_session(session_id: int, db: Session = Depends(get_db)):
    session = db.get(ChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    chats = db.exec(select(Chat).where(Chat.session_id == session_id).order_by(Chat.created_at)).all()
    return chats
    db.add(ai_message)
    db.commit()
    db.refresh(ai_message)

    return [user_message, ai_message]

@router.get("/session/{session_id}/chats", response_model=List[ChatResponse])
def get_chats_in_session(session_id: int, db: Session = Depends(get_db)):
    session = db.get(ChatSession, session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    chats = db.exec(select(Chat).where(Chat.session_id == session_id).order_by(Chat.created_at)).all()
    return chats
