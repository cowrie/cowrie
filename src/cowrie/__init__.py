from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("cowrie")
except PackageNotFoundError:
    # package is not installed
    pass
