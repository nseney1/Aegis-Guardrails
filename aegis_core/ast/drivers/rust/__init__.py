"""First-party, in-process Rust extraction. No Rust toolchain is executed."""
from .extractor import CAPABILITIES, parse

__all__ = ['CAPABILITIES', 'parse']
