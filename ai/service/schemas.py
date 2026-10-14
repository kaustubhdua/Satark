from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    text: str = Field(min_length=1, max_length=12_000)
    case_id: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("text")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("text must contain non-whitespace characters")
        return value


class Signal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    category: Literal["url", "ip", "language"]
    severity: Literal["info", "low", "medium", "high"]
    description: str
    evidence_excerpt: str = Field(max_length=300)


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"]
    case_id: str | None
    verdict: Literal["insufficient_evidence", "needs_review"]
    ai_status: Literal["disabled", "configured", "unavailable", "invalid_output"]
    summary: str = Field(max_length=1_500)
    signals: list[Signal] = Field(max_length=50)
    next_steps: list[str] = Field(max_length=8)
    disclaimer: str
