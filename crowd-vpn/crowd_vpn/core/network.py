"""Core network management for Crowd VPN."""

import asyncio
import socket
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class NodeType(Enum):
    """Node types in the crowd VPN network."""
    CLIENT = "client"
    RELAY = "relay"
    EXIT = "exit"
    HYBRID = "hybrid"  # Acts as both relay and exit


@dataclass
class NetworkNode:
    """Represents a node in the crowd VPN network."""
    node_id: str
    ip_address: str
    port: int
    node_type: NodeType
    public_key: bytes
    bandwidth_capacity: int  # KB/s
    latency: float  # ms
    reputation_score: float  # 0.0 to 1.0
    is_active: bool = True
    last_seen: float = 0.0


class NetworkManager:
    """Manages network connections and node discovery."""
    
    def __init__(self, listen_port: int = 8080, node_type: NodeType = NodeType.HYBRID):
        self.listen_port = listen_port
        self.node_type = node_type
        self.node_id = self._generate_node_id()
        self.peers: Dict[str, NetworkNode] = {}
        self.active_connections: Dict[str, asyncio.StreamWriter] = {}
        self.server: Optional[asyncio.Server] = None
        self.logger = logging.getLogger(__name__)
        
    def _generate_node_id(self) -> str:
        """Generate a unique node ID."""
        import hashlib
        import time
        
        hostname = socket.gethostname()
        timestamp = str(time.time())
        data = f"{hostname}:{self.listen_port}:{timestamp}".encode()
        return hashlib.sha256(data).hexdigest()[:16]
    
    async def start_server(self):
        """Start the network server to accept incoming connections."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client_connection,
                '0.0.0.0',
                self.listen_port
            )
            self.logger.info(f"Server started on port {self.listen_port}")
            async with self.server:
                await self.server.serve_forever()
        except Exception as e:
            self.logger.error(f"Failed to start server: {e}")
            raise
    
    async def _handle_client_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connections."""
        client_addr = writer.get_extra_info('peername')
        self.logger.info(f"New connection from {client_addr}")
        
        try:
            # Perform handshake and authentication
            await self._perform_handshake(reader, writer)
            
            # Handle ongoing communication
            await self._handle_peer_communication(reader, writer)
            
        except Exception as e:
            self.logger.error(f"Error handling client {client_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _perform_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Perform initial handshake with peer."""
        # Send our node information
        handshake_data = {
            'node_id': self.node_id,
            'node_type': self.node_type.value,
            'version': '0.1.0'
        }
        
        import json
        message = json.dumps(handshake_data).encode() + b'\n'
        writer.write(message)
        await writer.drain()
        
        # Receive peer information
        response = await reader.readline()
        if response:
            peer_data = json.loads(response.decode().strip())
            peer_id = peer_data.get('node_id')
            if peer_id:
                self.active_connections[peer_id] = writer
                self.logger.info(f"Handshake completed with peer {peer_id}")
    
    async def _handle_peer_communication(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle ongoing communication with a peer."""
        while True:
            try:
                data = await reader.read(4096)
                if not data:
                    break
                
                # Process the received data
                await self._process_peer_data(data, writer)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in peer communication: {e}")
                break
    
    async def _process_peer_data(self, data: bytes, writer: asyncio.StreamWriter):
        """Process data received from a peer."""
        # This is where we'd handle different types of messages:
        # - Traffic routing requests
        # - Peer discovery updates
        # - Heartbeat messages
        # - Bandwidth tests
        pass
    
    async def connect_to_peer(self, host: str, port: int) -> Optional[str]:
        """Connect to a peer node."""
        try:
            reader, writer = await asyncio.open_connection(host, port)
            
            # Perform handshake
            await self._perform_handshake(reader, writer)
            
            # Start handling communication in background
            asyncio.create_task(self._handle_peer_communication(reader, writer))
            
            self.logger.info(f"Connected to peer at {host}:{port}")
            return f"{host}:{port}"
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {host}:{port}: {e}")
            return None
    
    def add_peer(self, node: NetworkNode):
        """Add a peer to our known peers list."""
        self.peers[node.node_id] = node
        self.logger.info(f"Added peer {node.node_id} ({node.ip_address}:{node.port})")
    
    def remove_peer(self, node_id: str):
        """Remove a peer from our known peers list."""
        if node_id in self.peers:
            del self.peers[node_id]
            self.logger.info(f"Removed peer {node_id}")
    
    def get_best_peers(self, count: int = 5) -> List[NetworkNode]:
        """Get the best peers based on reputation and performance."""
        active_peers = [peer for peer in self.peers.values() if peer.is_active]
        # Sort by reputation score and latency
        sorted_peers = sorted(
            active_peers,
            key=lambda p: (p.reputation_score, -p.latency),
            reverse=True
        )
        return sorted_peers[:count]
    
    async def stop(self):
        """Stop the network manager and close all connections."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        for writer in self.active_connections.values():
            writer.close()
            await writer.wait_closed()
        
        self.active_connections.clear()
        self.logger.info("Network manager stopped")

