"""Animated CLI dashboard for AutoSecAudit.

Provides a real-time terminal UI with:
- Animated banner
- Live dashboard (attack queue, findings, stats, progress)
- Module execution status with ASCII art
- Color-coded severity with icons
- Animated progress bars with ETA
- Live statistics counter
"""
from __future__ import annotations

import io
import os
import sys
import time
import threading
from typing import Optional, Dict, List
from collections import Counter

# --- Force UTF-8 stdout on Windows ---
def _force_utf8_stdout() -> None:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        elif not isinstance(sys.stdout, io.TextIOWrapper) or \
             sys.stdout.encoding.lower().replace("-", "") != "utf8":
            sys.stdout = io.TextIOWrapper(
                sys.stdout.buffer, encoding="utf-8", errors="replace",
                line_buffering=True,
            )
    except Exception:
        pass

def _force_utf8_stderr() -> None:
    try:
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_force_utf8_stdout()
_force_utf8_stderr()

try:
    import colorama
    colorama.init(autoreset=True)
    _HAS_COLORAMA = True
except Exception:
    _HAS_COLORAMA = False

_FORCE_NO_COLOR = os.environ.get("NO_COLOR") is not None
_IS_TTY = sys.stdout.isatty()
_COLORS_ENABLED = _IS_TTY and not _FORCE_NO_COLOR

# Unicode support detection
_UNICODE_OK = False
try:
    sys.stdout.encode("utf-8")
    _UNICODE_OK = True
except Exception:
    _UNICODE_OK = False

# ANSI color codes
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_CLEAR_LINE = "\033[2K"
_CURSOR_UP = "\033[1A"
_CURSOR_DOWN = "\033[1B"

_CODES = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_cyan": "\033[96m",
    "bright_magenta": "\033[95m",
}

# Severity icons and colors
SEVERITY_ICONS = {
    "CRITICAL": ("[!!!]", "bright_red"),
    "HIGH":     ("[!! ]", "red"),
    "MEDIUM":   ("[!  ]", "yellow"),
    "LOW":      ("[.  ]", "blue"),
    "INFO":     ("[i  ]", "gray"),
}

# Module ASCII art icons
MODULE_ICONS = {
    "discovery":       "[~] Discovery",
    "headers":         "[H] Headers/TLS",
    "tls":             "[T] TLS Check",
    "xss":             "[X] XSS",
    "sqli":            "[S] SQLi",
    "nosqli":          "[N] NoSQLi",
    "command_injection":"[C] Cmd Injection",
    "ssti":            "[T] SSTI",
    "csrf":            "[C] CSRF",
    "cors":           ("[+] CORS"),
    "cookies":         "[c] Cookies",
    "clickjacking":    "[f] Clickjacking",
    "host_header":     "[h] Host Header",
    "cache":           "[$] Cache",
    "ssrf":            "[>] SSRF",
    "xxe":             "[<] XXE",
    "redirect":        "[r] Redirect",
    "graphql":         "[G] GraphQL",
    "websocket":       "[W] WebSocket",
    "jwt":             "[J] JWT",
    "cloud":           "[C] Cloud",
    "business_logic":  "[B] BizLogic",
    "param_mining":    "[p] ParamMine",
    "takeover":        "[T] Takeover",
    "subdomains":      "[S] Subdomains",
    "siteinfo":        "[i] OSINT",
    "exploit":         "[!] Exploit",
    "access_control":  "[A] AccessCtrl",
    "api":             "[A] API",
    "files":           "[f] Files",
    "infrastructure":  "[I] Infra",
    "cve":             "[C] CVE",
    "waf":             "[W] WAF",
    "deps":            "[D] Deps",
    "deserialization": "[d] Deserial",
    "prototype_pollution": "[P] ProtoPoll",
    "race_condition":  "[R] Race",
    "rate_limiting":   "[r] RateLimit",
    "info_disclosure": "[i] InfoDisc",
    "secrets_exposure":"[S] Secrets",
    "http_smuggling":  "[H] Smuggle",
    "upload":          "[U] Upload",
    "oauth":           "[O] OAuth",
    "saml":            "[S] SAML",
    "http_methods":    "[M] Methods",
    "mass_assignment": "[M] MassAssign",
    "ddos_protection": "[D] DDoS Check",
}

# Animated spinner frames
SPINNER_FRAMES = ["|", "/", "-", "\\"]
SPINNER_FRAMES_UNICODE = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

# --- Utility functions ---
def _wrap(text: str, color: str) -> str:
    if not _COLORS_ENABLED:
        return text
    return f"{_CODES.get(color, '')}{text}{_RESET}"

def _safe_print(msg: str) -> None:
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", "replace").decode("ascii"))

def _clear_line() -> None:
    if _COLORS_ENABLED and _IS_TTY:
        sys.stdout.write(_CLEAR_LINE)
        sys.stdout.flush()

def _move_cursor_up(lines: int) -> None:
    if _COLORS_ENABLED and _IS_TTY:
        sys.stdout.write(f"\033[{lines}A")
        sys.stdout.flush()

def _move_cursor_down(lines: int) -> None:
    if _COLORS_ENABLED and _IS_TTY:
        sys.stdout.write(f"\033[{lines}B")
        sys.stdout.flush()

# --- Banner ---
def print_banner() -> None:
    banner_art = r"""
    _    __        ______        __  ___           __
   / |  / /__     / ____/___  __/  |/  /___  _____/ /____  ____  ___
  /  | / / _ \   / __/ / __ \/ / /|_/ / __ \/ ___/ __/ _ \/ __ \/ _ \
 / /|  / /  __/ / /___/ / / / /  / / / /_/ / /__/ /_/  __/ / / /  __/
/_/ |_/_/\___/ /_____/_/ /_/_/  /_/_/\____/\___/\__/\___/_/ /_/\___/
"""
    if _UNICODE_OK:
        _safe_print(_wrap(banner_art, "cyan"))
    else:
        _safe_print(_wrap("=" * 50, "cyan"))
        _safe_print(_wrap("         AUTOSECAUDIT", "cyan"))
        _safe_print(_wrap("  Automated Security Assessment Tool", "cyan"))
        _safe_print(_wrap("=" * 50, "cyan"))
    _safe_print(_wrap("  v2.0  |  Adaptive Attack Engine  |  45+ Modules", "gray"))
    _safe_print("")

# --- Basic output functions ---
def info(msg: str) -> None:
    _safe_print(_wrap(f"[+] {msg}", "green"))

def warn(msg: str) -> None:
    _safe_print(_wrap(f"[!] {msg}", "yellow"))

def error(msg: str) -> None:
    _safe_print(_wrap(f"[-] {msg}", "red"))

def finding(severity: str, msg: str) -> None:
    icon, color = SEVERITY_ICONS.get(severity.upper(), ("[?]", "gray"))
    _safe_print(_wrap(f" {icon} {severity.upper():8s} {msg}", color))

def module_start(module_key: str) -> None:
    icon = MODULE_ICONS.get(module_key, f"[?] {module_key}")
    _safe_print(_wrap(f"  >>> {icon}", "bright_cyan"))

def module_done(module_key: str, findings_count: int = 0) -> None:
    icon = MODULE_ICONS.get(module_key, f"[?] {module_key}")
    if findings_count > 0:
        _safe_print(_wrap(f"  <<< {icon}  (+{findings_count} findings)", "bright_green"))
    else:
        _safe_print(_wrap(f"  <<< {icon}  (clean)", "gray"))

# --- Progress bar ---
def progress_bar(percent: float, width: int = 25, prefix: str = "") -> None:
    percent = max(0.0, min(100.0, percent))
    filled = int(width * percent / 100)
    if _UNICODE_OK:
        bar = "█" * filled + "░" * (width - filled)
    else:
        bar = "#" * filled + "-" * (width - filled)
    try:
        sys.stdout.write(f"\r{_wrap(f'  [{bar}]', 'cyan')} {percent:5.1f}% {prefix}")
        sys.stdout.flush()
        if percent >= 100:
            print()
    except Exception:
        pass

# --- Spinner ---
class Spinner:
    """Animated spinner for long operations."""

    def __init__(self, text: str = "Processing"):
        self.text = text
        self.frames = SPINNER_FRAMES if not _UNICODE_OK else SPINNER_FRAMES_UNICODE
        self.idx = 0
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._animate, daemon=True)
        self.thread.start()

    def _animate(self):
        while self.running:
            frame = self.frames[self.idx % len(self.frames)]
            sys.stdout.write(f"\r  {frame} {self.text}...")
            sys.stdout.flush()
            self.idx += 1
            time.sleep(0.1)

    def stop(self, final_text: str = ""):
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
        _clear_line()
        if final_text:
            info(final_text)

# --- Dashboard ---
class Dashboard:
    """Real-time dashboard displaying scan progress, queue, findings, and stats."""

    def __init__(self):
        self.findings: List[dict] = []
        self.findings_by_severity = Counter()
        self.modules_running: List[str] = []
        self.modules_completed: List[str] = []
        self.queue_items: List[dict] = []
        self.technologies: List[str] = []
        self.endpoints_count = 0
        self.parameters_count = 0
        self.iteration = 0
        self.max_iterations = 3
        self.target = ""
        self.mode = ""
        self.start_time = 0.0
        self._lock = threading.Lock()

    def set_target(self, target: str, mode: str):
        self.target = target
        self.mode = mode
        self.start_time = time.time()

    def update_queue(self, items: List[dict]):
        with self._lock:
            self.queue_items = items

    def add_finding(self, finding):
        with self._lock:
            self.findings.append(finding)
            self.findings_by_severity[finding.severity.value] += 1

    def set_iteration(self, current: int, max_iter: int):
        with self._lock:
            self.iteration = current
            self.max_iterations = max_iter

    def module_started(self, key: str):
        with self._lock:
            if key not in self.modules_running:
                self.modules_running.append(key)

    def module_finished(self, key: str):
        with self._lock:
            if key in self.modules_running:
                self.modules_running.remove(key)
            if key not in self.modules_completed:
                self.modules_completed.append(key)

    def set_surface(self, endpoints: int = 0, parameters: int = 0, techs: List[str] = None):
        with self._lock:
            self.endpoints_count = endpoints
            self.parameters_count = parameters
            if techs:
                self.technologies = techs

    def render_dashboard(self):
        """Render the full dashboard to terminal."""
        with self._lock:
            elapsed = time.time() - self.start_time if self.start_time else 0
            mins, secs = divmod(int(elapsed), 60)

            # Header
            print()
            _safe_print(_wrap("=" * 60, "cyan"))
            _safe_print(_wrap(f"  TARGET: {self.target}", "bold"))
            _safe_print(_wrap(f"  MODE: {self.mode.upper()}  |  ELAPSED: {mins}m {secs}s", "gray"))
            _safe_print(_wrap("=" * 60, "cyan"))

            # Surface info
            if self.technologies:
                tech_str = ", ".join(self.technologies[:8])
                _safe_print(_wrap(f"  Technologies: {tech_str}", "bright_cyan"))
            _safe_print(_wrap(f"  Endpoints: {self.endpoints_count}  |  Parameters: {self.parameters_count}", "gray"))

            # Findings summary
            print()
            _safe_print(_wrap("  FINDINGS:", "bold"))
            crit = self.findings_by_severity.get("CRITICAL", 0)
            high = self.findings_by_severity.get("HIGH", 0)
            med = self.findings_by_severity.get("MEDIUM", 0)
            low = self.findings_by_severity.get("LOW", 0)
            info_c = self.findings_by_severity.get("INFO", 0)
            total = crit + high + med + low + info_c

            if crit > 0:
                _safe_print(_wrap(f"    CRITICAL: {crit}", "bright_red"))
            if high > 0:
                _safe_print(_wrap(f"    HIGH:     {high}", "red"))
            if med > 0:
                _safe_print(_wrap(f"    MEDIUM:   {med}", "yellow"))
            if low > 0:
                _safe_print(_wrap(f"    LOW:      {low}", "blue"))
            if info_c > 0:
                _safe_print(_wrap(f"    INFO:     {info_c}", "gray"))
            if total == 0:
                _safe_print(_wrap("    (none yet)", "gray"))

            # Attack queue
            if self.queue_items:
                print()
                _safe_print(_wrap("  ATTACK QUEUE:", "bold"))
                for i, item in enumerate(self.queue_items[:8], 1):
                    name = item.get("module", "").upper()
                    prio = item.get("priority", 0)
                    ran = item.get("ran", False)
                    status = _wrap("[DONE]", "gray") if ran else _wrap("[NEXT]", "bright_green")
                    _safe_print(f"    {i:2d}. {name:20s} {prio:.2f}  {status}")

            # Running modules
            if self.modules_running:
                print()
                _safe_print(_wrap("  RUNNING:", "bold"))
                for mod in self.modules_running[:6]:
                    icon = MODULE_ICONS.get(mod, f"[?] {mod}")
                    _safe_print(_wrap(f"    {icon} ...", "bright_cyan"))

            # Iteration
            if self.iteration > 0:
                print()
                _safe_print(_wrap(f"  Learning iteration: {self.iteration}/{self.max_iterations}", "magenta"))

            print()
            _safe_print(_wrap("-" * 60, "gray"))

# --- Prompt functions ---
def prompt(msg: str) -> str:
    return input(_wrap(f"{msg} ", "bold")).strip()

def prompt_options(msg: str, options: list) -> str:
    _safe_print(_wrap(msg, "bold"))
    for i, opt in enumerate(options, 1):
        _safe_print(f"  [{i}] {opt}")
    while True:
        choice = input(_wrap("Choice: ", "bold")).strip()
        try:
            idx = int(choice)
            if 1 <= idx <= len(options):
                return options[idx - 1]
        except ValueError:
            pass
        for opt in options:
            if choice.lower() == opt.lower():
                return opt
        error("Invalid choice, try again.")

# --- Scan animation ---
def animate_scan_start():
    """Animate the start of a scan."""
    _safe_print("")
    _safe_print(_wrap("  Initializing adaptive attack engine...", "bright_cyan"))
    time.sleep(0.3)
    _safe_print(_wrap("  Loading module registry...", "cyan"))
    time.sleep(0.2)
    _safe_print(_wrap("  Building attack knowledge graph...", "cyan"))
    time.sleep(0.2)
    _safe_print(_wrap("  Configuring rules engine...", "cyan"))
    time.sleep(0.2)
    _safe_print(_wrap("  Starting reconnaissance...", "bright_green"))
    _safe_print("")

def animate_discovery():
    """Animate the discovery phase."""
    _safe_print(_wrap("  [PHASE 1] RECONNAISSANCE", "bright_cyan"))
    _safe_print(_wrap("  " + "-" * 40, "gray"))

def animate_testing():
    """Animate the testing phase."""
    _safe_print("")
    _safe_print(_wrap("  [PHASE 2] VULNERABILITY TESTING", "bright_cyan"))
    _safe_print(_wrap("  " + "-" * 40, "gray"))

def animate_exploitation():
    """Animate the exploitation phase."""
    _safe_print("")
    _safe_print(_wrap("  [PHASE 3] SAFE VALIDATION", "bright_cyan"))
    _safe_print(_wrap("  " + "-" * 40, "gray"))

def animate_report():
    """Animate report generation."""
    _safe_print("")
    _safe_print(_wrap("  [PHASE 4] REPORT GENERATION", "bright_cyan"))
    _safe_print(_wrap("  " + "-" * 40, "gray"))

def print_scan_complete(findings_count: int, duration: float, report_paths: List[str]):
    """Print the final scan summary."""
    mins, secs = divmod(int(duration), 60)
    _safe_print("")
    _safe_print(_wrap("=" * 60, "green"))
    _safe_print(_wrap("  SCAN COMPLETE", "bright_green"))
    _safe_print(_wrap(f"  Duration: {mins}m {secs}s  |  Findings: {findings_count}", "green"))
    if report_paths:
        _safe_print(_wrap("  Reports:", "green"))
        for p in report_paths:
            _safe_print(_wrap(f"    -> {p}", "gray"))
    _safe_print(_wrap("=" * 60, "green"))
    _safe_print("")
