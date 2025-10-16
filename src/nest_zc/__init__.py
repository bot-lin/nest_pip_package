from .hello import say_hello
from .robot import Robot
__all__ = ["say_hello", "Robot"]

try:
    from importlib.metadata import version
    __version__ = version("nest-zc")
except Exception:
    __version__ = "0.0.0"
