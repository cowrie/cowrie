import sys
from twisted.python import log

try:
    import cowrie._version as __version__  # noqa: F401
except ModuleNotFoundError:
    log.err("Cowrie is not installed. Run `pip install -e .` to install Cowrie into your virtual enviroment")
    sys.exit(1)
