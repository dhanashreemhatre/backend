
from pydantic import BaseModel
from datetime import datetime
from typing import List,Optional

# Add these to your schemas.py
class UserCreate(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
class ChatCreate(BaseModel):
    content: str

class ChatResponse(BaseModel):
    id: int
    content: str
    role: str
    created_at: datetime

class ChatSessionCreate(BaseModel):
    title: str

class ChatSessionResponse(BaseModel):
    id: int
    title: str
    created_at: datetime
    chats: List[ChatResponse] = []
