
from sqlmodel import Field, SQLModel, Relationship
from datetime import datetime
from typing import Optional, List
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
class UserBase(SQLModel):
    username: str = Field(unique=True, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class User(UserBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    hashed_password: str
    sessions: List["ChatSession"] = Relationship(back_populates="user")

    @staticmethod
    def get_password_hash(password: str) -> str:
        return pwd_context.hash(password)

    def verify_password(self, plain_password: str) -> bool:
        return pwd_context.verify(plain_password, self.hashed_password)

class ChatSessionBase(SQLModel):
    title: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ChatSession(ChatSessionBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: User = Relationship(back_populates="sessions")
    chats: List["Chat"] = Relationship(back_populates="session")

class ChatBase(SQLModel):
    content: str
    role: str  # "user" or "ai"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Chat(ChatBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="chatsession.id")
    session: ChatSession = Relationship(back_populates="chats")
