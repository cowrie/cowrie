import sys
import warnings

from cryptography.utils import CryptographyDeprecationWarning

# Fixed upstream by twisted/twisted#12453 (not yet in any released Twisted as
# of 25.5.0). Drop this filter once requirements.txt pins a Twisted release
# that includes that fix.
warnings.filterwarnings(
    "ignore",
    category=CryptographyDeprecationWarning,
    module=r"twisted\.conch\.ssh\.transport",
)

from twisted.python import log

try:
    import cowrie._version as cowrie_version

    __version__ = cowrie_version
except ModuleNotFoundError:
    log.err(
        "Cowrie is not installed. Run `pip install -e .` to install Cowrie into your virtual enviroment"
    )
    sys.exit(1)
