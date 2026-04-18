# Developed by Galal Noaman – RedShadow_V4
# For educational and lawful use only.
# Do not copy, redistribute, or resell without written permission.

# RedShadow_v4/modules/utils.py

import yaml
import os
import threading
from termcolor import cprint

# ─── Internal Cache ───
# Thread-safe config cache with lock.
# Many modules call load_config() from threads (ThreadPool in passive, secret,
# probe, etc). If two threads both see _config_cache as None simultaneously,
# they both read the file and one overwrites the other's result.
# A threading.Lock() ensures only one thread populates the cache.
_config_cache = None
_cache_lock   = threading.Lock()


def load_config(path="config.yaml", section=None, verbose=True, force_reload=False):
    """
    Loads YAML configuration file and returns the full config or a specific section.
    Uses an internal cache unless force_reload=True is set.
    Thread-safe: protected by a module-level lock.

    Args:
        path (str):          Path to YAML config file.
        section (str):       Optional section to extract from the config.
        verbose (bool):      Print status messages.
        force_reload (bool): Bypass cache and reload fresh.

    Returns:
        dict: Entire config or specific section (default: entire config)
    """
    global _config_cache
    default_config = {}

    with _cache_lock:
        # ── Return cached result if available and not forcing reload ──
        if _config_cache is not None and not force_reload:
            return _config_cache.get(section, {}) if section else _config_cache

        # ── Fallback if config file is missing ──
        if not os.path.exists(path):
            if verbose:
                cprint(f"[!] Warning: Config file not found at {path}. Using default settings.", "yellow")
            _config_cache = default_config
            return default_config if section is None else default_config.get(section, {})

        # ── Load and parse YAML ──
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}

            if not isinstance(config, dict):
                raise ValueError("Invalid YAML format: top-level structure must be a dictionary.")

            _config_cache = config

            if verbose:
                cprint(f"[✓] Loaded config from {path}", "green")

            return config.get(section, {}) if section else config

        except yaml.YAMLError as parse_err:
            cprint(f"[!] YAML parse error in {path}: {parse_err}", "red")
        except Exception as e:
            cprint(f"[!] Failed to load config from {path}: {e}", "red")

        _config_cache = default_config
        return default_config if section is None else default_config.get(section, {})