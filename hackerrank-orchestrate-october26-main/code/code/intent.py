from __future__ import annotations

from enum import Enum
import re
import unicodedata


class RequestIntent(str, Enum):
    DELETION = "DELETION"
    NOT_DELETION = "NOT_DELETION"
    UNCERTAIN = "UNCERTAIN"


_DELETE_PATTERNS = (
    r"\bdelet(?:e|es|ed|ing|ion|ions)\b",
    r"\beras(?:e|ed|es|ing|ure)\b",
    r"\bremov(?:e|ed|al|ing)\b.{0,50}\b(account|profile|data|personal information|records?|search results?)\b",
    r"\b(account|profile|data|personal information|records?)\b.{0,55}\b(?:already )?(?:deleted|removed|erased)\b",
    r"\b(?:account|profile|data|records?)\b.{0,55}\b(?:gone|no longer (?:exists?|present))\b",
    r"\b(close|shut down)\b.{0,35}\b(account|profile)\b",
    r"\bforget me\b",
    r"\b(?:eliminar|eliminación|borrar|borrado|suprimir|supresión)\b",
    r"\b(?:supprimer|suppression|effacer|effacement)\b",
    r"\b(?:excluir|exclusão|apagar|deletar)\b",
    r"\b(?:lösch(?:en|ung)|entfern(?:en|ung))\b",
    r"\b(?:cancellare|cancellazione|eliminare)\b",
    r"削除|消去|削除依頼|退会",
    r"삭제|탈퇴|계정.{0,8}삭제",
)
_NON_DELETE_PATTERNS = (
    r"\b(access|access request|copy of my data|download my data|export my data)\b",
    r"\b(correct|correction|update|change|replace)\b.{0,45}\b(email|phone|address|name|profile|number)\b",
    r"\b(marketing opt.?out|opt.?out of marketing|stop marketing|stop (?:the )?promotional emails?|unsubscribe)\b",
    r"\bremove me from (?:the )?marketing lists? only\b",
    r"\bdownload (?:my )?(?:account )?information in a portable format\b",
    r"\bcopy of (?:last year's|my) invoices?\b",
    r"\bmobile number\b.{0,35}\b(out of date|incorrect|wrong)\b",
    r"\bleave (?:the )?account active\b",
    r"\bdo not delete\b|\bdon't delete\b|\bnot requesting deletion\b|\bnot asking you to delete\b",
    r"\bkeep my account\b|\bdo not close my account\b|\bdon't close my account\b",
)


def classify_request(text: str) -> RequestIntent:
    """Classify only explicit intent; leave unmatched wording for review/fallback."""
    value = unicodedata.normalize("NFKC", str(text or "")).casefold()
    has_deletion = any(re.search(pattern, value, re.IGNORECASE) for pattern in _DELETE_PATTERNS)
    has_non_delete = any(re.search(pattern, value, re.IGNORECASE) for pattern in _NON_DELETE_PATTERNS)
    if has_non_delete and not has_deletion:
        return RequestIntent.NOT_DELETION
    if has_deletion:
        if re.search(r"\b(?:do not|don't|never|not)\b.{0,24}\b(?:delete|erase|remove|close)\b", value):
            return RequestIntent.NOT_DELETION
        return RequestIntent.DELETION
    if has_non_delete:
        return RequestIntent.NOT_DELETION
    return RequestIntent.UNCERTAIN
