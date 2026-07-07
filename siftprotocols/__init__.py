"""SiFT v1.0 -- a Simple File Transfer protocol with modern, authenticated cryptography.

Shared implementation imported by the server, the client, the test suite, the
attack harness, and the web demo.
"""

from .monitoring import SecurityMonitor, get_monitor
from .siftcmd import SiFT_CMD, SiFT_CMD_Error
from .siftdnl import SiFT_DNL, SiFT_DNL_Error
from .siftlogin import LoginGuard, SiFT_LOGIN, SiFT_LOGIN_Error
from .siftmtp import SiFT_MTP, SiFT_MTP_Error
from .siftupl import SiFT_UPL, SiFT_UPL_Error

__all__ = [
    "SiFT_MTP", "SiFT_MTP_Error",
    "SiFT_LOGIN", "SiFT_LOGIN_Error", "LoginGuard",
    "SiFT_CMD", "SiFT_CMD_Error",
    "SiFT_UPL", "SiFT_UPL_Error",
    "SiFT_DNL", "SiFT_DNL_Error",
    "SecurityMonitor", "get_monitor",
]

__version__ = "1.0.0"
