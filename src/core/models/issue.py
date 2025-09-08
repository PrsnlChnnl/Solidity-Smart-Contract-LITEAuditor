from enum import Enum
from pydantic import BaseModel
from typing import Optional


class Severity(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Issue(BaseModel):
    """Модель для представления найденной уязвимости."""
    title: str
    description: str
    severity: Severity
    line_number: Optional[int] = None
    contract_name: Optional[str] = None
    function_name: Optional[str] = None

    def __str__(self):
        return f"[{self.severity.value}] {self.title} (Line: {self.line_number})"