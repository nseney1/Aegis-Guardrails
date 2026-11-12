"""Installed resource namespace for absorbed Teams templates.

Read trusted bundled assets with ``importlib.resources.files(__package__)``.
TA-4 moves the legacy templates here; TA-0 reserves the package without copying
leased source bytes. Importing this namespace performs no runtime discovery,
workspace reads, host registration or template installation.
"""
