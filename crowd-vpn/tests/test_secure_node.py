#!/usr/bin/env python3
"""Test script for running a secure Crowd VPN node."""

import asyncio
import logging
import signal
import sys
from pathlib import Path

from crowd_vpn.core.secure_network import SecureNetworkManager, PeerRole
from crowd_vpn.crypto.secure_crypto import ProductionCryptoManager
from crowd_vpn.config.secure_config import SecureConfigManager


def setup_logging():
    """Setup logging for the test."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('test_secure_node.log')
        ]
    )
    
    # Set specific loggers
    logging.getLogger('crowd_vpn.core.secure_network.security').setLevel(logging.WARNING)
    

class SecureTestNode:
    """Test implementation of a secure VPN node."""
    
    def __init__(self, port: int = 8080, host: str = '127.0.0.1'):
        self.port = port
        self.host = host
        self.running = False
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.config_manager = SecureConfigManager()
        self.network_manager = SecureNetworkManager(
            listen_port=port,
            listen_host=host,
            role=PeerRole.HYBRID
        )
        
        # Generate keys for testing
        self.network_manager.crypto_manager.generate_identity_keypair()
    
    async def start(self):
        """Start the secure test node."""
        if self.running:
            return
        
        self.running = True
        self.logger.info(f"Starting secure test node on {self.host}:{self.port}")
        
        try:
            # Start network manager (this will run forever)
            await self.network_manager.start()
        except Exception as e:
            self.logger.error(f"Failed to start secure node: {e}")
            raise
    
    async def stop(self):
        """Stop the secure test node."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping secure test node")
        
        # Stop network manager
        await self.network_manager.stop()
        
        self.logger.info("Secure test node stopped")
    
    def get_stats(self):
        """Get node statistics."""
        stats = self.network_manager.get_network_stats()
        return stats


async def main():
    """Main function to run the secure test node."""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Parse command line arguments
    port = 8080
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            logger.error(f"Invalid port number: {sys.argv[1]}")
            sys.exit(1)
    
    # Create and start node
    node = SecureTestNode(port=port)
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(node.stop())
    
    # Register signal handlers (Unix/Linux only)
    if hasattr(signal, 'SIGINT'):
        signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("=" * 60)
        logger.info("SECURE CROWD VPN NODE TEST")
        logger.info("=" * 60)
        logger.info(f"Node ID: {node.network_manager.node_id[:16]}...")
        logger.info(f"Role: {node.network_manager.role.value}")
        logger.info(f"Listening on: {node.host}:{node.port}")
        logger.info(f"Public Key Fingerprint: {node.network_manager.crypto_manager.get_public_key_fingerprint()}")
        logger.info("=" * 60)
        
        # Display security status
        config = node.config_manager
        logger.info("Security Configuration:")
        logger.info(f"  - Authentication Required: {config.security_policy.require_authentication}")
        logger.info(f"  - Rate Limiting: {config.security_policy.enable_rate_limiting}")
        logger.info(f"  - Intrusion Detection: {config.security_policy.enable_intrusion_detection}")
        logger.info(f"  - PBKDF2 Iterations: {config.crypto.pbkdf2_iterations:,}")
        logger.info(f"  - Perfect Forward Secrecy: {config.crypto.enable_perfect_forward_secrecy}")
        
        # Display security recommendations
        recommendations = config.get_security_recommendations()
        if recommendations:
            logger.warning("Security Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                logger.warning(f"  {i}. {rec}")
        
        logger.info("=" * 60)
        logger.info("Node is ready to accept connections!")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 60)
        
        # Start the node (this will run until interrupted)
        await node.start()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # Ensure cleanup
        await node.stop()
        
        # Display final stats
        stats = node.get_stats()
        logger.info("Final Statistics:")
        logger.info(f"  - Total Peers: {stats['total_peers']}")
        logger.info(f"  - Authenticated Peers: {stats['authenticated_peers']}")
        logger.info(f"  - Active Connections: {stats['active_connections']}")
        logger.info(f"  - Messages Sent: {stats['messages_sent']}")
        logger.info(f"  - Messages Received: {stats['messages_received']}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

