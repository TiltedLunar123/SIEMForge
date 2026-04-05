"""Terminal display helpers — colors, banners, status output."""
from __future__ import annotations

import os
import sys

from siemforge._version import VERSION


# ──────────────────────────────────────────────
# ANSI COLORS (respects NO_COLOR convention)
# ──────────────────────────────────────────────

_NO_COLOR = bool(os.environ.get("NO_COLOR"))


class Color:
    RED = "" if _NO_COLOR else "\033[91m"
    GREEN = "" if _NO_COLOR else "\033[92m"
    YELLOW = "" if _NO_COLOR else "\033[93m"
    BLUE = "" if _NO_COLOR else "\033[94m"
    MAGENTA = "" if _NO_COLOR else "\033[95m"
    CYAN = "" if _NO_COLOR else "\033[96m"
    WHITE = "" if _NO_COLOR else "\033[97m"
    BOLD = "" if _NO_COLOR else "\033[1m"
    DIM = "" if _NO_COLOR else "\033[2m"
    RESET = "" if _NO_COLOR else "\033[0m"


C = Color  # short alias used throughout


def _supports_unicode() -> bool:
    """Check if the terminal can handle Unicode box-drawing characters."""
    try:
        encoding = sys.stdout.encoding or ""
        if encoding.lower().replace("-", "") in ("utf8", "utf16", "utf32"):
            return True
        "\u2550".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


_UNICODE = _supports_unicode()
_DIV_CHAR = "\u2550" if _UNICODE else "="
_LINE_CHAR = "\u2500" if _UNICODE else "-"
DIV = f"{C.BLUE}{_DIV_CHAR * 70}{C.RESET}"

_OK = "[\u2713]" if _UNICODE else "[+]"
_ERR = "[\u2717]" if _UNICODE else "[X]"
_BUL = "\u2022" if _UNICODE else "*"


BANNER = rf"""
{C.CYAN}{C.BOLD}
  ____  ___ _____ __  __ _____
 / ___|/ _ \_   _|  \/  |  ___|__  _ __ __ _  ___
 \___ \ | | || | | |\/| | |_ / _ \| '__/ _` |/ _ \
  ___) | |_| || | | |  | |  _| (_) | | | (_| |  __/
 |____/ \___/ |_| |_|  |_|_|  \___/|_|  \__, |\___|
                                         |___/
{C.RESET}
{C.DIM}  SIEM Detection Content Toolkit  v{VERSION}
  Sigma Rules | Sysmon Config | Wazuh Integration
  Author : Jude Hilgendorf
  GitHub : github.com/TiltedLunar123{C.RESET}
"""


def header(title: str) -> None:
    print(f"\n{DIV}")
    print(f"  {C.BOLD}{C.CYAN}[ {title} ]{C.RESET}")
    print(DIV)


def ok(msg: str) -> None:
    print(f"  {C.GREEN}{_OK}{C.RESET} {msg}")


def info(msg: str) -> None:
    print(f"  {C.BLUE}[i]{C.RESET} {msg}")


def warn(msg: str) -> None:
    print(f"  {C.YELLOW}[!]{C.RESET} {msg}")


def err(msg: str) -> None:
    print(f"  {C.RED}{_ERR}{C.RESET} {msg}")


def bullet(msg: str) -> None:
    print(f"    {C.DIM}{_BUL}{C.RESET} {msg}")
