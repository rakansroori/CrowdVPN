"""Main VPN node application that acts as both client and server."""

import asyncio
import logging
import argparse
import signal
import sys
from typing import Optional

from .core.network import NetworkManager, NodeType
from .core.router import TrafficRouter, RoutingAlgorithm
from .p2p.discovery import PeerDiscovery
from .crypto.encryption import CryptoManager


class CrowdVPNNode:
    """Main VPN node that handles both client and server functionality."""
    
    def __init__(self, 
                 port: int = 8080,
                 node_type: NodeType = NodeType.HYBRID,
                 bootstrap_nodes: list = None,
                 routing_algorithm: RoutingAlgorithm = RoutingAlgorithm.REPUTATION_BASED):
        
        self.port = port
        self.node_type = node_type
        self.bootstrap_nodes = bootstrap_nodes or []
        self.running = False
        
        # Initialize components
        self.network_manager = NetworkManager(port, node_type)
        self.crypto_manager = CryptoManager()
        self.traffic_router = TrafficRouter(self.network_manager, routing_algorithm)
        self.peer_discovery = PeerDiscovery(self.network_manager, bootstrap_nodes)
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
        self._setup_logging()
        
        # Generate or load cryptographic keys
        self._setup_crypto()
    
    def _setup_logging(self):
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('crowd_vpn_node.log')
            ]
        )
    
    def _setup_crypto(self):
        """Setup cryptographic keys."""
        try:
            # Try to load existing keys
            with open('node_private.pem', 'rb') as f:
                private_pem = f.read()
            with open('node_public.pem', 'rb') as f:
                public_pem = f.read()
            
            self.crypto_manager.load_keypair(private_pem, public_pem)
            self.logger.info("Loaded existing key pair")
            
        except FileNotFoundError:
            # Generate new keys
            private_pem, public_pem = self.crypto_manager.generate_keypair()
            
            # Save keys to files
            with open('node_private.pem', 'wb') as f:
                f.write(private_pem)
            with open('node_public.pem', 'wb') as f:
                f.write(public_pem)
            
            self.logger.info("Generated new key pair")
    
    async def start(self):
        """Start the VPN node."""
        if self.running:
            return
        
        self.running = True
        self.logger.info(f"Starting Crowd VPN Node on port {self.port}")
        self.logger.info(f"Node ID: {self.network_manager.node_id}")
        self.logger.info(f"Node Type: {self.node_type.value}")
        self.logger.info(f"Public Key Hash: {self.crypto_manager.get_public_key_hash()}")
        
        try:
            # Start peer discovery
            await self.peer_discovery.start()
            
            # Start network server
            server_task = asyncio.create_task(self.network_manager.start_server())
            
            # Start periodic maintenance tasks
            maintenance_task = asyncio.create_task(self._maintenance_loop())
            
            # Wait for tasks
            await asyncio.gather(server_task, maintenance_task)
            
        except Exception as e:
            self.logger.error(f"Error starting node: {e}")
            await self.stop()
    
    async def stop(self):
        """Stop the VPN node."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping Crowd VPN Node")
        
        # Stop components
        await self.peer_discovery.stop()
        await self.network_manager.stop()
        
        self.logger.info("Node stopped successfully")
    
    async def _maintenance_loop(self):
        """Periodic maintenance tasks."""
        while self.running:
            try:
                # Clean up inactive routes
                self.traffic_router.cleanup_inactive_routes()
                
                # Log statistics
                peer_stats = self.peer_discovery.get_peer_stats()
                self.logger.info(f"Node stats: {peer_stats}")
                
                # Sleep for 60 seconds
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in maintenance loop: {e}")
                await asyncio.sleep(10)
    
    async def connect_to_network(self, bootstrap_node: str):
        """Connect to the VPN network via a bootstrap node."""
        host, port_str = bootstrap_node.split(':')
        port = int(port_str)
        
        connection_id = await self.network_manager.connect_to_peer(host, port)
        if connection_id:
            self.logger.info(f"Successfully connected to bootstrap node {bootstrap_node}")
            return True
        else:
            self.logger.error(f"Failed to connect to bootstrap node {bootstrap_node}")
            return False
    
    def get_node_status(self) -> dict:
        """Get current node status."""
        return {
            'node_id': self.network_manager.node_id,
            'node_type': self.node_type.value,
            'port': self.port,
            'running': self.running,
            'connected_peers': len(self.network_manager.active_connections),
            'known_peers': len(self.network_manager.peers),
            'active_routes': len(self.traffic_router.active_routes),
            'public_key_hash': self.crypto_manager.get_public_key_hash()
        }


async def main():
    """Main entry point for the VPN node."""
    parser = argparse.ArgumentParser(description='Crowd VPN Node')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--type', choices=['client', 'relay', 'exit', 'hybrid'], 
                       default='hybrid', help='Node type')
    parser.add_argument('--bootstrap', action='append', 
                       help='Bootstrap node address (host:port)')
    parser.add_argument('--routing', choices=['random', 'shortest_path', 'load_balanced', 'reputation_based'],
                       default='reputation_based', help='Routing algorithm')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Convert string arguments to enums
    node_type = NodeType(args.type)
    routing_algorithm = RoutingAlgorithm(args.routing)
    
    # Create and start node
    node = CrowdVPNNode(
        port=args.port,
        node_type=node_type,
        bootstrap_nodes=args.bootstrap or [],
        routing_algorithm=routing_algorithm
    )
    
    # Setup signal handlers for graceful shutdown
    def signal_handler():
        print("\nShutting down...")
        asyncio.create_task(node.stop())
    
    # Register signal handlers
    if sys.platform != 'win32':
        loop = asyncio.get_event_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    
    try:
        await node.start()
    except KeyboardInterrupt:
        print("\nReceived interrupt, shutting down...")
        await node.stop()
    except Exception as e:
        print(f"Error: {e}")
        await node.stop()
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())

