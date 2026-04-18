# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/logger.py  v2
# Structured per-run logging with proper log levels, stack traces,
# and write-failure resilience.
#

#   - Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
#   - Full stack traces written to file on exceptions
#   - _write() has retry logic and stderr fallback — never crashes the tool
#   - Stage timing stored and retrievable
#   - Findings summary written at run end
#   - get_logger() always returns a valid instance (never None)

import os
import sys
import json
import time
import traceback
import threading
from datetime import datetime
from termcolor import cprint

# Log levels (numeric, matches Python logging)
DEBUG    = 10
INFO     = 20
WARNING  = 30
ERROR    = 40
CRITICAL = 50

_LEVEL_NAMES = {DEBUG: "DEBUG", INFO: "INFO", WARNING: "WARNING",
                ERROR: "ERROR", CRITICAL: "CRITICAL"}

_logger_instance = None
_logger_lock     = threading.Lock()


def get_logger():
    """Always returns a valid logger — creates a no-op instance if not initialised."""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = RunLogger()
    return _logger_instance


def init_logger(output_dir="outputs", debug=False, quiet=False):
    """Initialise the global logger for a new run."""
    global _logger_instance
    with _logger_lock:
        _logger_instance = RunLogger(output_dir=output_dir, debug=debug, quiet=quiet)
    return _logger_instance


class RunLogger:
    """
    Structured per-run logger.
    Writes JSON-lines to: <output_dir>/logs/run_<timestamp>.log
    Tracks: stage timings, warning/error counts, findings summary.
    Never raises — all write failures are handled gracefully.
    """

    def __init__(self, output_dir="outputs", debug=False, quiet=False):
        self.debug        = debug
        self.quiet        = quiet
        self.min_level    = DEBUG if debug else INFO
        self.warnings     = 0
        self.errors       = 0
        self.run_start    = time.time()
        self._lock        = threading.Lock()
        self._stage_times = {}    # stage_name → {"start": t, "end": t, "state": s}
        self._findings    = []    # list of finding summaries for run_end entry
        self._write_ok    = True  # False after repeated write failures

        # Create logs directory
        try:
            log_dir = os.path.join(output_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_path = os.path.join(log_dir, f"run_{ts}.log")
        except Exception as ex:
            # Can't create log dir — log to temp as fallback
            import tempfile
            self.log_path = os.path.join(tempfile.gettempdir(), f"redshadow_{int(time.time())}.log")
            sys.stderr.write(f"[logger] Could not create log dir: {ex}, using {self.log_path}\n")

        self._write_entry({"event": "run_start",
                           "timestamp": datetime.utcnow().isoformat() + "Z",
                           "debug_mode": debug})

    # ─────────────────────────────────────
    # Core write — never raises
    # ─────────────────────────────────────

    def _write_entry(self, entry: dict):
        """
        Write a log entry to disk. Three layers of resilience:
        1. Normal write
        2. Retry once on IOError
        3. Fall back to stderr — never crashes the tool
        """
        if not self._write_ok:
            return

        entry["_ts"] = datetime.utcnow().isoformat() + "Z"
        line = json.dumps(entry, default=str) + "\n"

        with self._lock:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line)
            except IOError:
                try:
                    # Retry once
                    time.sleep(0.05)
                    with open(self.log_path, "a", encoding="utf-8") as f:
                        f.write(line)
                except Exception as ex:
                    # Fall back to stderr so important entries are not lost
                    sys.stderr.write(f"[logger fallback] {line.strip()} | write error: {ex}\n")
                    self._write_ok = False   # stop attempting file writes
            except Exception as ex:
                sys.stderr.write(f"[logger fallback] {line.strip()} | error: {ex}\n")
                self._write_ok = False

    # ─────────────────────────────────────
    # Public API
    # ─────────────────────────────────────

    def log(self, level: int, event: str, msg: str = "", **kwargs):
        """Generic log at any level."""
        if level < self.min_level:
            return
        entry = {"event": event, "level": _LEVEL_NAMES.get(level, "INFO")}
        if msg:
            entry["msg"] = msg
        entry.update(kwargs)
        self._write_entry(entry)

        # Console output based on level and quiet mode
        if not self.quiet or level >= ERROR:
            if level >= ERROR:
                cprint(f"  [✗] {msg}", "red")
            elif level == WARNING and self.debug:
                cprint(f"  [!] {msg}", "yellow")
            elif self.debug:
                cprint(f"  [D] {msg}", "cyan")

    def debug_msg(self, msg: str, **kwargs):
        self.log(DEBUG, "debug", msg, **kwargs)

    def info(self, msg: str, stage: str = "", **kwargs):
        entry = {"event": "info", "msg": msg}
        if stage:
            entry["stage"] = stage
        entry.update(kwargs)
        self._write_entry(entry)
        if self.debug and not self.quiet:
            cprint(f"  [D] {msg}", "cyan")

    def warning(self, msg: str, stage: str = "", **kwargs):
        self.warnings += 1
        entry = {"event": "warning", "level": "WARNING", "msg": msg}
        if stage:
            entry["stage"] = stage
        entry.update(kwargs)
        self._write_entry(entry)
        if self.debug:
            cprint(f"  [!] {msg}", "yellow")

    def error(self, msg: str, stage: str = "", exc: Exception = None, **kwargs):
        """
        Log an error. If exc is provided, writes full stack trace to log file.
        Errors are always shown on console regardless of quiet mode.
        """
        self.errors += 1
        entry = {"event": "error", "level": "ERROR", "msg": msg}
        if stage:
            entry["stage"] = stage
        if exc is not None:
            entry["exception_type"] = type(exc).__name__
            entry["exception_msg"]  = str(exc)
            # Full stack trace in log file
            entry["traceback"] = traceback.format_exc()
        entry.update(kwargs)
        self._write_entry(entry)
        cprint(f"  [✗] {msg}", "red")
        if exc and self.debug:
            cprint(f"      {traceback.format_exc().splitlines()[-1]}", "yellow")

    def critical(self, msg: str, exc: Exception = None, **kwargs):
        """Critical failure — always logged and always shown."""
        self.errors += 1
        entry = {"event": "critical", "level": "CRITICAL", "msg": msg}
        if exc is not None:
            entry["exception_type"] = type(exc).__name__
            entry["exception_msg"]  = str(exc)
            entry["traceback"]      = traceback.format_exc()
        entry.update(kwargs)
        self._write_entry(entry)
        cprint(f"  [✗✗] CRITICAL: {msg}", "red")

    def stage_start(self, name: str):
        self._stage_times[name] = {"start": time.time(), "state": "RUNNING"}
        self._write_entry({"event": "stage_start", "stage": name})

    def stage_end(self, name: str, elapsed: float = 0.0,
                  state: str = "PASSED", error: str = ""):
        if name in self._stage_times:
            self._stage_times[name]["end"]   = time.time()
            self._stage_times[name]["state"] = state
        entry = {"event": "stage_end", "stage": name,
                 "state": state, "elapsed_s": round(elapsed, 2)}
        if error:
            entry["error"] = error
        self._write_entry(entry)

    def skipped(self, stage: str, reason: str = ""):
        entry = {"event": "skipped", "stage": stage}
        if reason:
            entry["reason"] = reason
        self._write_entry(entry)

    def finding(self, finding_type: str, host: str,
                detail: str, confidence: str = "", severity: str = ""):
        """Record a significant finding for the run summary."""
        record = {"type": finding_type, "host": host, "detail": detail}
        if confidence:
            record["confidence"] = confidence
        if severity:
            record["severity"] = severity
        self._findings.append(record)
        self._write_entry({"event": "finding", **record})

    def run_summary(self):
        """Write final run summary entry and print stats to console."""
        elapsed = round(time.time() - self.run_start, 2)

        stage_summary = {
            name: {"state": data.get("state", "UNKNOWN"),
                   "elapsed_s": round(data.get("end", data["start"]) - data["start"], 2)}
            for name, data in self._stage_times.items()
        }

        summary = {
            "event":         "run_end",
            "elapsed_s":     elapsed,
            "warnings":      self.warnings,
            "errors":        self.errors,
            "findings":      len(self._findings),
            "stage_summary": stage_summary,
            "log_file":      self.log_path,
        }
        self._write_entry(summary)

        if not self.quiet:
            cprint(f"\n  [📋] Run log: {self.log_path}", "cyan")
            if self.warnings:
                cprint(f"       Warnings : {self.warnings}", "yellow")
            if self.errors:
                cprint(f"       Errors   : {self.errors}", "red")
            if not self._write_ok:
                cprint("       [!] Some log entries could not be written to disk", "yellow")

        return summary

    def get_stage_timing(self, stage_name: str) -> float:
        """Return elapsed seconds for a completed stage, or 0.0."""
        data = self._stage_times.get(stage_name, {})
        start = data.get("start", 0)
        end   = data.get("end", start)
        return round(end - start, 2)

    def get_stats(self) -> dict:
        return {
            "warnings":   self.warnings,
            "errors":     self.errors,
            "log_path":   self.log_path,
            "write_ok":   self._write_ok,
            "findings":   len(self._findings),
        }