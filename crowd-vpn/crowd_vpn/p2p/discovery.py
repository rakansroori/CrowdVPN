"""Peer discovery and network bootstrapping for Crowd VPN."""

import asyncio
import json
import logging
import socket
import time
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict

from ..core.network import NetworkNode, NodeType


@dataclass
class PeerAnnouncement:
    """Represents a peer announcement message."""
    node_id: str
    ip_address: str
    port: int
    node_type: str
    public_key_hash: str
    bandwidth_capacity: int
    timestamp: float
    signature: str = ""


class PeerDiscovery:
    """Handles peer discovery and network bootstrapping."""
    
    def __init__(self, network_manager, bootstrap_nodes: List[str] = None):
        self.network_manager = network_manager
        self.bootstrap_nodes = bootstrap_nodes or []
        self.known_peers: Dict[str, PeerAnnouncement] = {}
        self.discovery_interval = 30  # seconds
        self.peer_timeout = 300  # 5 minutes
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.discovery_task: Optional[asyncio.Task] = None
        
        # DHT-like distributed hash table for peer storage
        self.dht_buckets: Dict[str, Set[str]] = {}
    
    async def start(self):
        """Start the peer discovery service."""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Starting peer discovery service")
        
        # Connect to bootstrap nodes first
        await self._connect_bootstrap_nodes()
        
        # Start periodic discovery
        self.discovery_task = asyncio.create_task(self._discovery_loop())
    
    async def stop(self):
        """Stop the peer discovery service."""
        self.running = False
        
        if self.discovery_task:
            self.discovery_task.cancel()
            try:
                await self.discovery_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Peer discovery service stopped")
    
    async def _connect_bootstrap_nodes(self):
        """Connect to initial bootstrap nodes."""
        for node_addr in self.bootstrap_nodes:
            try:
                host, port_str = node_addr.split(':')
                port = int(port_str)
                
                connection_id = await self.network_manager.connect_to_peer(host, port)
                if connection_id:
                    self.logger.info(f"Connected to bootstrap node {node_addr}")
                    
                    # Request peer list from bootstrap node
                    await self._request_peer_list(host, port)
                    
            except Exception as e:
                self.logger.warning(f"Failed to connect to bootstrap node {node_addr}: {e}")
    
    async def _discovery_loop(self):
        """Main discovery loop."""
        while self.running:
            try:
                # Announce ourselves to known peers
                await self._announce_to_peers()
                
                # Clean up expired peers
                self._cleanup_expired_peers()
                
                # Try to discover new peers
                await self._discover_new_peers()
                
                # Update network manager with discovered peers
                self._update_network_manager()
                
                await asyncio.sleep(self.discovery_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
                await asyncio.sleep(5)
    
    async def _announce_to_peers(self):
        """Announce our presence to known peers."""
        announcement = PeerAnnouncement(
            node_id=self.network_manager.node_id,
            ip_address=self._get_external_ip(),
            port=self.network_manager.listen_port,
            node_type=self.network_manager.node_type.value,
            public_key_hash="placeholder",  # Would be actual key hash
            bandwidth_capacity=1024,  # Would be measured
            timestamp=time.time()
        )
        
        # Send announcement to all connected peers
        for peer_id, writer in self.network_manager.active_connections.items():
            try:
                await self._send_announcement(writer, announcement)
            except Exception as e:
                self.logger.warning(f"Failed to announce to peer {peer_id}: {e}")
    
    async def _send_announcement(self, writer: asyncio.StreamWriter, announcement: PeerAnnouncement):
        """Send peer announcement message."""
        message = {
            'type': 'peer_announcement',
            'data': asdict(announcement)
        }
        
        json_message = json.dumps(message).encode() + b'\n'
        writer.write(json_message)
        await writer.drain()
    
    async def _request_peer_list(self, host: str, port: int):
        """Request list of known peers from a node."""
        try:
            # This would be implemented as part of the network protocol
            message = {
                'type': 'peer_list_request',
                'requester_id': self.network_manager.node_id
            }
            
            # For now, just log the request
            self.logger.info(f"Requesting peer list from {host}:{port}")
            
        except Exception as e:
            self.logger.error(f"Error requesting peer list from {host}:{port}: {e}")
    
    def _cleanup_expired_peers(self):
        """Remove expired peers from known peers list."""
        current_time = time.time()
        expired_peers = []
        
        for peer_id, announcement in self.known_peers.items():
            if current_time - announcement.timestamp > self.peer_timeout:
                expired_peers.append(peer_id)
        
        for peer_id in expired_peers:
            del self.known_peers[peer_id]
            self.logger.info(f"Removed expired peer {peer_id}")
    
    async def _discover_new_peers(self):
        """Attempt to discover new peers through various methods."""
        # Method 1: Ask existing peers for their peer lists
        await self._request_peers_from_connected()
        
        # Method 2: DHT-style lookup (simplified)
        await self._dht_lookup()
        
        # Method 3: Local network discovery (optional)
        await self._local_network_discovery()
    
    async def _request_peers_from_connected(self):
        """Request peer lists from currently connected peers."""
        for peer_id, writer in self.network_manager.active_connections.items():
            try:
                message = {
                    'type': 'get_peer_list',
                    'requester_id': self.network_manager.node_id
                }
                
                json_message = json.dumps(message).encode() + b'\n'
                writer.write(json_message)
                await writer.drain()
                
            except Exception as e:
                self.logger.warning(f"Failed to request peers from {peer_id}: {e}")
    
    async def _dht_lookup(self):
        """Perform DHT-style peer lookup."""
        # Simplified DHT implementation
        # In a real implementation, this would use proper Kademlia or similar
        
        target_id = self.network_manager.node_id
        closest_peers = self._find_closest_peers(target_id, 5)
        
        for peer_announcement in closest_peers:
            try:
                # Try to connect to the peer if not already connected
                if peer_announcement.node_id not in self.network_manager.active_connections:
                    await self.network_manager.connect_to_peer(
                        peer_announcement.ip_address,
                        peer_announcement.port
                    )
            except Exception as e:
                self.logger.warning(f"Failed to connect to DHT peer {peer_announcement.node_id}: {e}")
    
    async def _local_network_discovery(self):
        """Discover peers on the local network using UDP broadcast."""
        try:
            # Send UDP broadcast to discover local peers
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            
            discovery_message = {
                'type': 'peer_discovery',
                'node_id': self.network_manager.node_id,
                'port': self.network_manager.listen_port
            }
            
            message = json.dumps(discovery_message).encode()
            sock.sendto(message, ('255.255.255.255', 8888))  # Broadcast port
            
            # Listen for responses
            try:
                while True:
                    data, addr = sock.recvfrom(1024)
                    response = json.loads(data.decode())
                    
                    if response.get('type') == 'peer_discovery_response':
                        peer_host, peer_port = addr[0], response.get('port')
                        if peer_port:
                            asyncio.create_task(
                                self.network_manager.connect_to_peer(peer_host, peer_port)
                            )
            except socket.timeout:
                pass
            
            sock.close()
            
        except Exception as e:
            self.logger.debug(f"Local network discovery error: {e}")
    
    def _find_closest_peers(self, target_id: str, count: int) -> List[PeerAnnouncement]:
        """Find closest peers to a target ID using XOR distance."""
        def xor_distance(id1: str, id2: str) -> int:
            # Simple XOR distance calculation
            return int(id1[:8], 16) ^ int(id2[:8], 16)
        
        peers_with_distance = [
            (announcement, xor_distance(target_id, announcement.node_id))
            for announcement in self.known_peers.values()
        ]
        
        # Sort by distance and return top N
        peers_with_distance.sort(key=lambda x: x[1])
        return [peer[0] for peer in peers_with_distance[:count]]
    
    def _update_network_manager(self):
        """Update network manager with discovered peers."""
        for announcement in self.known_peers.values():
            # Convert announcement to NetworkNode
            node = NetworkNode(
                node_id=announcement.node_id,
                ip_address=announcement.ip_address,
                port=announcement.port,
                node_type=NodeType(announcement.node_type),
                public_key=b"placeholder",  # Would be actual public key
                bandwidth_capacity=announcement.bandwidth_capacity,
                latency=0.0,  # Would be measured
                reputation_score=0.5,  # Would be calculated
                last_seen=announcement.timestamp
            )
            
            # Add to network manager if not already present
            if node.node_id not in self.network_manager.peers:
                self.network_manager.add_peer(node)
    
    def handle_peer_announcement(self, announcement_data: dict):
        """Handle incoming peer announcement."""
        try:
            announcement = PeerAnnouncement(**announcement_data)
            
            # Verify the announcement (signature check would go here)
            if self._verify_announcement(announcement):
                self.known_peers[announcement.node_id] = announcement
                self.logger.info(f"Received valid peer announcement from {announcement.node_id}")
            else:
                self.logger.warning(f"Invalid peer announcement from {announcement.node_id}")
                
        except Exception as e:
            self.logger.error(f"Error handling peer announcement: {e}")
    
    def _verify_announcement(self, announcement: PeerAnnouncement) -> bool:
        """Verify the authenticity of a peer announcement."""
        # In a real implementation, this would verify the signature
        # For now, just do basic validation
        
        if not announcement.node_id or not announcement.ip_address:
            return False
        
        if announcement.port <= 0 or announcement.port > 65535:
            return False
        
        if announcement.timestamp > time.time() + 60:  # Future timestamp
            return False
        
        return True
    
    def _get_external_ip(self) -> str:
        """Get external IP address."""
        try:
            # This is a simple method; in production you'd want more robust detection
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except Exception:
            return "127.0.0.1"  # Fallback to localhost
    
    def get_peer_stats(self) -> dict:
        """Get statistics about discovered peers."""
        return {
            'total_known_peers': len(self.known_peers),
            'active_connections': len(self.network_manager.active_connections),
            'bootstrap_nodes': len(self.bootstrap_nodes),
            'discovery_running': self.running
        }

