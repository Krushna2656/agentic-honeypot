from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class Message(BaseModel):
    sender: str = Field(..., example="scammer")
    text: str = Field(..., example="Verify your account immediately")
    timestamp: datetime = Field(..., example="2026-01-29T18:00:00")

    # Optional (professional + future safe)
    messageId: Optional[str] = Field(default=None, example="msg_001")
    source: Optional[str] = Field(default=None, example="mock_scammer_api")


class IncomingMessage(BaseModel):
    sessionId: str = Field(..., example="abc123")
    message: Message
    conversationHistory: List[Message] = Field(default_factory=list)

    # ✅ FIX: mutable default should use default_factory
    metadata: Dict[str, Any] = Field(default_factory=dict)
