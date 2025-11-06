"""Compatibility shim: re-export NetworkScanner from network_scanner.

Some modules import `NetworkScanner` from `scanner`. The implementation
is in `network_scanner.py` — provide a shim so those imports keep working.
"""
from network_scanner import NetworkScanner

__all__ = ["NetworkScanner"]
"""Compatibility shim: re-export NetworkScanner from network_scanner.

Some modules import `NetworkScanner` from `scanner`. The implementation
is in `network_scanner.py` — provide a shim so those imports keep working.
"""
from network_scanner import NetworkScanner

__all__ = ["NetworkScanner"]
