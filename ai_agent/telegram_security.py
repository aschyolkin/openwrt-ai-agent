from __future__ import annotations

import html
import re
import time
import unicodedata
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable


TELEGRAM_MESSAGE_LIMIT = 4096


def split_message(text: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> list[str]:
    """Split plain (pre-HTML) text into chunks, preferring paragraph/line/word
    boundaries so markdown markers (e.g. '**bold**') are not cut in half and
    each chunk can be converted to balanced Telegram HTML independently."""
    if limit < 1:
        raise ValueError("limit must be positive")
    text = str(text)
    if not text:
        return [""]
    chunks: list[str] = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break
        window = text[:limit]
        for boundary in ("\n\n", "\n", " "):
            cut = window.rfind(boundary)
            if cut > 0:
                chunks.append(text[:cut])
                text = text[cut + len(boundary):]
                break
        else:
            chunks.append(window)
            text = text[limit:]
    return chunks or [""]


def escape_html(text: str) -> str:
    return html.escape(str(text), quote=False)


# Inline markers only — deliberately excludes '\n' from the matched span so a
# single call never crosses a line boundary. Multi-line fenced code blocks and
# tables are handled at the block level in markdown_to_telegram_html, below.
_INLINE_PATTERN = re.compile(
    r"`(?P<code>[^`\n]+?)`"
    r"|\*\*(?P<bold>[^\n]+?)\*\*"
    r"|__(?P<bold2>[^\n]+?)__"
    r"|(?<!\*)\*(?!\*)(?P<italic>[^*\n]+?)(?<!\*)\*(?!\*)"
    r"|(?<!_)_(?!_)(?P<italic2>[^_\n]+?)(?<!_)_(?!_)"
    r"|\[(?P<linktext>[^\]\n]+)\]\((?P<linkurl>[^)\s]+)\)"
)

_HEADING_RE = re.compile(r"^ {0,3}#{1,6}\s+(.*?)\s*#*\s*$")
_TABLE_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$")


def _convert_inline(text: str) -> str:
    """Convert inline Markdown emphasis/links on a single line/segment to Telegram
    HTML; everything unmatched is HTML-escaped, never left as raw '<'/'&' etc."""
    parts: list[str] = []
    pos = 0
    for match in _INLINE_PATTERN.finditer(text):
        if match.start() > pos:
            parts.append(escape_html(text[pos:match.start()]))
        group = match.lastgroup
        if group == "code":
            parts.append(f"<code>{escape_html(match.group('code'))}</code>")
        elif group in ("bold", "bold2"):
            inner = match.group("bold") if group == "bold" else match.group("bold2")
            parts.append(f"<b>{escape_html(inner)}</b>")
        elif group in ("italic", "italic2"):
            inner = match.group("italic") if group == "italic" else match.group("italic2")
            parts.append(f"<i>{escape_html(inner)}</i>")
        elif group == "linktext":
            url = html.escape(match.group("linkurl"), quote=True)
            parts.append(f'<a href="{url}">{escape_html(match.group("linktext"))}</a>')
        pos = match.end()
    parts.append(escape_html(text[pos:]))
    return "".join(parts)


def _display_width(text: str) -> int:
    """Approximate on-screen cell width: emoji/symbol/flag glyphs and East Asian
    wide/fullwidth characters render as ~2 monospace cells, not 1 — padding a
    <pre> grid by len() alone (character count) is what made columns with
    ✅/🇸🇪-style emoji drift out of alignment."""
    width = 0
    for ch in text:
        if unicodedata.combining(ch):
            continue
        cp = ord(ch)
        if unicodedata.east_asian_width(ch) in ("W", "F") or 0x1F000 <= cp <= 0x1FFFF or 0x2190 <= cp <= 0x2BFF:
            width += 2
        else:
            width += 1
    return width


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _format_table(rows: list[list[str]]) -> str:
    """Telegram HTML has no table element; render as a fixed-width plain-text
    grid inside <pre> so columns line up in the client's monospace font."""
    width = max((len(row) for row in rows), default=0)
    col_widths = [max((_display_width(row[i]) if i < len(row) else 0) for row in rows) for i in range(width)]
    lines = []
    for row in rows:
        cells = [_pad(row[i] if i < len(row) else "", col_widths[i]) for i in range(width)]
        lines.append(" | ".join(cells).rstrip())
    return f"<pre>{escape_html(chr(10).join(lines))}</pre>"


def _convert_blocks(text: str) -> list[str]:
    """Convert a conservative subset of Markdown (as commonly emitted by LLMs)
    into a list of self-contained, tag-balanced Telegram HTML blocks: '#'-headings
    become bold lines, fenced code blocks and pipe tables become <pre> blocks
    (Telegram has no heading/table elements), and inline emphasis/code/links are
    converted line-by-line. Everything else is HTML-escaped; unmatched/unbalanced
    markers are left as literal (escaped) characters rather than breaking output.
    Each returned block is independently valid HTML so callers can pack them into
    size-limited messages without ever splitting inside a tag."""
    lines = str(text).split("\n")
    blocks: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]

        if line.strip().startswith("```"):
            fence_body: list[str] = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                fence_body.append(lines[i])
                i += 1
            if i < n:
                i += 1  # consume closing fence
            blocks.append(f"<pre>{escape_html(chr(10).join(fence_body))}</pre>")
            continue

        heading = _HEADING_RE.match(line)
        if heading:
            blocks.append(f"<b>{_convert_inline(heading.group(1))}</b>")
            i += 1
            continue

        if line.strip().startswith("|") and i + 1 < n and _TABLE_SEPARATOR_RE.match(lines[i + 1]):
            table_lines = [line]
            i += 2  # header row consumed above, skip the '---' separator row
            while i < n and lines[i].strip().startswith("|"):
                table_lines.append(lines[i])
                i += 1
            rows = [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in table_lines]
            blocks.append(_format_table(rows))
            continue

        blocks.append(_convert_inline(line))
        i += 1
    return blocks


def markdown_to_telegram_html(text: str) -> str:
    """Convert Markdown to a single Telegram-HTML string (no length limit applied).
    For anything that will actually be sent through the Bot API, use
    markdown_to_telegram_chunks instead — HTML markup expands the character count
    past the plain-text length, so slicing pre-conversion text at 4096 chars (as
    this function's output alone would need) can still exceed Telegram's limit."""
    return "\n".join(_convert_blocks(text))


def _split_oversized_block(block: str, limit: int) -> list[str]:
    """A single converted block (e.g. one huge <pre> table, or one huge plain
    line) exceeded the message limit by itself. Re-derive a safely splittable
    form rather than slicing the HTML directly, which could cut a tag in half."""
    pre_match = re.match(r"^<pre>(.*)</pre>$", block, re.DOTALL)
    if pre_match:
        budget = limit - len("<pre></pre>")
        inner_lines = pre_match.group(1).split("\n")
        chunks: list[str] = []
        current: list[str] = []
        current_len = 0
        for line in inner_lines:
            add_len = len(line) + (1 if current else 0)
            if current and current_len + add_len > budget:
                chunks.append(f"<pre>{chr(10).join(current)}</pre>")
                current, current_len = [line], len(line)
            else:
                current.append(line)
                current_len += add_len
        if current:
            chunks.append(f"<pre>{chr(10).join(current)}</pre>")
        return chunks or ["<pre></pre>"]
    # Plain-text fallback: strip any markup this block carries and hard-split
    # the escaped text — guarantees valid (if unformatted) HTML either way.
    plain = html.unescape(re.sub(r"<[^>]+>", "", block))
    return split_message(plain, limit) if plain else [""]


def markdown_to_telegram_chunks(text: str, limit: int = TELEGRAM_MESSAGE_LIMIT) -> list[str]:
    """Convert Markdown to Telegram HTML and pack it into <= `limit`-character
    messages, splitting only at block boundaries (never inside a tag)."""
    blocks = _convert_blocks(text)
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    def flush() -> None:
        nonlocal current, current_len
        if current:
            chunks.append("\n".join(current))
            current, current_len = [], 0

    for block in blocks:
        if len(block) > limit:
            flush()
            chunks.extend(_split_oversized_block(block, limit))
            continue
        add_len = len(block) + (1 if current else 0)
        if current and current_len + add_len > limit:
            flush()
        current.append(block)
        current_len += len(block) + (1 if len(current) > 1 else 0)
    flush()
    return chunks or [""]


@dataclass
class TelegramUpdateGuard:
    allowed_chat_ids: frozenset[int]
    max_message_length: int = 8192
    rate_limit: int = 10
    rate_window_seconds: float = 60.0
    clock: Callable[[], float] = time.monotonic
    _seen: deque[int] = field(default_factory=lambda: deque(maxlen=2048), init=False)
    _events: dict[int, deque[float]] = field(default_factory=dict, init=False)

    def _chat_id(self, update: dict[str, Any]) -> int | None:
        message = update.get("message")
        callback = update.get("callback_query")
        source = message if isinstance(message, dict) else callback if isinstance(callback, dict) else None
        if not isinstance(source, dict):
            return None
        if isinstance(source.get("message"), dict):
            source = source["message"]
        chat = source.get("chat")
        try:
            return int(chat["id"]) if isinstance(chat, dict) else None
        except (KeyError, TypeError, ValueError):
            return None

    def accept(self, update: dict[str, Any]) -> tuple[bool, str, int | None]:
        """Return (accepted, reason, chat_id); reject before Core API access."""
        if not isinstance(update, dict):
            return False, "invalid_update", None
        try:
            update_id = int(update["update_id"])
        except (KeyError, TypeError, ValueError):
            return False, "missing_update_id", None
        if update_id in self._seen:
            return False, "duplicate_update", None
        self._seen.append(update_id)
        chat_id = self._chat_id(update)
        if chat_id is None or chat_id not in self.allowed_chat_ids:
            return False, "chat_not_allowed", chat_id
        message = update.get("message")
        if isinstance(message, dict) and isinstance(message.get("text"), str):
            if not message["text"].strip() or len(message["text"]) > self.max_message_length:
                return False, "message_limit", chat_id
        now = self.clock()
        events = self._events.setdefault(chat_id, deque())
        while events and now - events[0] >= self.rate_window_seconds:
            events.popleft()
        if len(events) >= self.rate_limit:
            return False, "rate_limited", chat_id
        events.append(now)
        return True, "accepted", chat_id

    def session_id(self, chat_id: int) -> str:
        if chat_id not in self.allowed_chat_ids:
            raise ValueError("chat is not allowed")
        return f"telegram:{chat_id}"
