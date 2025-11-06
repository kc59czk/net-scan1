"""Compatibility shim: re-export Database from db_manager.

Some parts of the code import `Database` from `database`. The
implementation lives in `db_manager.py` in this workspace — provide a
tiny shim so those imports continue to work.
"""
from db_manager import Database

__all__ = ["Database"]
