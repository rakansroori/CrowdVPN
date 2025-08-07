"""Crowd VPN - Decentralized peer-to-peer VPN system."""

__version__ = "0.1.0"
__author__ = "Crowd VPN Team"
__description__ = "A decentralized VPN where every client acts as a server node"

from .core.network import NetworkManager
from .core.router import TrafficRouter
from .p2p.discovery import PeerDiscovery
from .crypto.encryption import CryptoManager

__all__ = [
    'NetworkManager',
    'TrafficRouter', 
    'PeerDiscovery',
    'CryptoManager'
]

