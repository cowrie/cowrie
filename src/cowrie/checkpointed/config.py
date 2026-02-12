"""
Configuration helpers for checkpointed image environments.

Reads environment definitions from cowrie.cfg sections following the pattern:

  [checkpointed_<name>]
  type = dgd|lambdamoo|smalltalk|lispmachine
  host = localhost
  port = 6047
  ... (adapter-specific options)

Multiple environments can be configured simultaneously and managed
through the EnvironmentBridge.
"""

from __future__ import annotations

from typing import Any

from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.checkpointed.bridge import EnvironmentBridge


# Mapping of config keys to adapter constructor kwargs, per environment type
_TYPE_CONFIG: dict[str, dict[str, tuple[str, Any]]] = {
    "dgd": {
        "host": ("host", "localhost"),
        "port": ("port", 6047),
        "admin_user": ("admin_user", "admin"),
        "admin_password": ("admin_password", ""),
        "statedump_dir": ("statedump_dir", ""),
    },
    "lambdamoo": {
        "host": ("host", "localhost"),
        "port": ("port", 7777),
        "wizard_name": ("wizard_name", "wizard"),
        "wizard_password": ("wizard_password", ""),
        "http_port": ("http_port", 0),
        "use_toaststunt": ("use_toaststunt", False),
    },
    "smalltalk": {
        "host": ("host", "localhost"),
        "port": ("port", 1701),
        "variant": ("variant", "pharo"),
        "http_port": ("http_port", 8080),
        "image_path": ("image_path", ""),
        "gst_binary": ("gst_binary", "gst"),
    },
    "lispmachine": {
        "host": ("host", "localhost"),
        "port": ("port", 23),
        "emulator_type": ("emulator_type", "genera"),
        "world_dir": ("world_dir", ""),
        "nfs_share": ("nfs_share", ""),
    },
}

# Type normalization map
_TYPE_ALIASES: dict[str, str] = {
    "dgd": "dgd",
    "dworkin": "dgd",
    "lpc": "dgd",
    "lambdamoo": "lambdamoo",
    "moo": "lambdamoo",
    "toaststunt": "lambdamoo",
    "moor": "lambdamoo",
    "smalltalk": "smalltalk",
    "pharo": "smalltalk",
    "squeak": "smalltalk",
    "gnu-smalltalk": "smalltalk",
    "gst": "smalltalk",
    "lispmachine": "lispmachine",
    "lisp-machine": "lispmachine",
    "genera": "lispmachine",
    "open-genera": "lispmachine",
    "vlm": "lispmachine",
    "cadr": "lispmachine",
    "lambda": "lispmachine",
    "lmi-lambda": "lispmachine",
    "meroko": "lispmachine",
    "explorer": "lispmachine",
}


def load_environments_from_config(
    bridge: EnvironmentBridge | None = None,
) -> EnvironmentBridge:
    """
    Load checkpointed environment definitions from cowrie.cfg.

    Scans for sections named [checkpointed_<name>] and creates
    the corresponding adapter for each.

    Returns the populated EnvironmentBridge.
    """
    if bridge is None:
        bridge = EnvironmentBridge()

    sections = CowrieConfig.sections()
    for section in sections:
        if not section.startswith("checkpointed_"):
            continue

        name = section[len("checkpointed_"):]
        if not name:
            continue

        env_type_raw = CowrieConfig.get(section, "type", fallback="")
        if not env_type_raw:
            log.msg(
                f"Checkpointed config: section [{section}] has no 'type', "
                f"skipping"
            )
            continue

        env_type = _TYPE_ALIASES.get(env_type_raw.lower())
        if env_type is None:
            log.msg(
                f"Checkpointed config: unknown type {env_type_raw!r} in "
                f"[{section}], skipping. Valid types: "
                f"{sorted(_TYPE_ALIASES.keys())}"
            )
            continue

        # Build kwargs from config
        kwargs: dict[str, Any] = {}
        type_config = _TYPE_CONFIG.get(env_type, {})

        for config_key, (kwarg_name, default) in type_config.items():
            if isinstance(default, bool):
                kwargs[kwarg_name] = CowrieConfig.getboolean(
                    section, config_key, fallback=default
                )
            elif isinstance(default, int):
                kwargs[kwarg_name] = CowrieConfig.getint(
                    section, config_key, fallback=default
                )
            elif isinstance(default, float):
                kwargs[kwarg_name] = CowrieConfig.getfloat(
                    section, config_key, fallback=default
                )
            else:
                kwargs[kwarg_name] = CowrieConfig.get(
                    section, config_key, fallback=default
                )

        # Handle variant/emulator overrides from type aliases
        if env_type_raw.lower() in ("pharo", "squeak", "gnu-smalltalk", "gst"):
            variant = env_type_raw.lower().replace("-", "")
            if variant == "gst":
                variant = "gnu"
            kwargs["variant"] = variant
        elif env_type_raw.lower() in (
            "genera", "open-genera", "vlm", "cadr",
            "lambda", "lmi-lambda", "meroko", "explorer",
        ):
            emulator = env_type_raw.lower()
            if emulator in ("open-genera", "vlm"):
                emulator = "genera"
            elif emulator == "lmi-lambda":
                emulator = "lambda"
            elif emulator == "explorer":
                emulator = "meroko"
            kwargs["emulator_type"] = emulator
        elif env_type_raw.lower() == "toaststunt":
            kwargs["use_toaststunt"] = True

        try:
            bridge.create_environment(name, env_type, **kwargs)
            log.msg(
                f"Checkpointed config: loaded environment {name!r} "
                f"(type={env_type})"
            )
        except Exception as e:
            log.err(
                f"Checkpointed config: failed to create environment "
                f"{name!r}: {e}"
            )

    # Set default if configured
    default_name = CowrieConfig.get(
        "checkpointed", "default", fallback=""
    )
    if default_name and default_name in bridge.environments:
        bridge.set_default(default_name)

    return bridge
