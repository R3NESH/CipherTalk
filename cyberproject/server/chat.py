from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

class MessageSend(BaseModel):
    room: str
    text: str

@router.post("/send")
async def send_message(_: MessageSend):
    return {"msg": "chat stored (mock)"}

@router.get("/history")
async def get_chat_history(room: str):
    # Return a couple of mock messages in expected shape
    return [
        {"user": "one", "text": "Hello from mock", "timestamp": "2025-01-01T00:00:00Z"},
        {"user": "two", "text": f"Welcome to room {room}", "timestamp": "2025-01-01T00:00:05Z"}
    ]
