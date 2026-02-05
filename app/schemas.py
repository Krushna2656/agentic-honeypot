from pydantic import BaseModel, Field, field_validator
from pydantic.config import ConfigDict
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone


class Message(BaseModel):
    sender: str = Field(..., example="scammer")
    text: str = Field(..., example="Verify your account immediately")

    # ✅ Accepts: ISO string OR epoch milliseconds (problem statement format)
    timestamp: datetime = Field(..., example=1770005528731)

    # Optional
    messageId: Optional[str] = Field(default=None, example="msg_001")
    source: Optional[str] = Field(default=None, example="mock_scammer_api")

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, v):
        """
        Accept:
          - epoch ms int (e.g., 1770005528731)
          - epoch seconds int (e.g., 1770005528)
          - ISO datetime string
          - datetime
        """
        if v is None:
            raise ValueError("timestamp is required")

        # already datetime
        if isinstance(v, datetime):
            # if naive, attach UTC to be safe
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v

        # epoch numeric
        if isinstance(v, (int, float)):
            # if it's ms (very large)
            if v > 10_000_000_000:
                return datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(v, tz=timezone.utc)

        # string
        if isinstance(v, str):
            s = v.strip()

            # numeric string epoch
            if s.isdigit():
                n = int(s)
                if n > 10_000_000_000:
                    return datetime.fromtimestamp(n / 1000.0, tz=timezone.utc)
                return datetime.fromtimestamp(n, tz=timezone.utc)

            # ISO string
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                raise ValueError("Invalid timestamp format. Use epoch ms or ISO datetime.")

        raise ValueError("Invalid timestamp type. Use epoch ms (int) or ISO datetime string.")


class IncomingMessage(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    sessionId: str = Field(..., example="abc123")
    message: Message

    # ✅ Accepts both keys:
    # - "conversationHistory": [...]
    # - "history": [...]
    conversationHistory: List[Message] = Field(default_factory=list, alias="history")

    metadata: Dict[str, Any] = Field(default_factory=dict)