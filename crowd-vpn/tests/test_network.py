"""Tests for core network functionality."""

import pytest
import asyncio
from crowd_vpn.core.network import NetworkManager, NetworkNode, NodeType


@pytest.fixture
def network_manager():
    """Create a test network manager."""
    return NetworkManager(listen_port=9999, node_type=NodeType.HYBRID)


@pytest.fixture
def sample_node():
    """Create a sample network node for testing."""
    return NetworkNode(
        node_id="test_node_123",
        ip_address="192.168.1.100",
        port=8080,
        node_type=NodeType.RELAY,
        public_key=b"test_public_key",
        bandwidth_capacity=1024,
        latency=50.0,
        reputation_score=0.8
    )


class TestNetworkManager:
    """Test cases for NetworkManager."""
    
    def test_node_id_generation(self, network_manager):
        """Test that node ID is generated correctly."""
        assert network_manager.node_id is not None
        assert len(network_manager.node_id) == 16  # Should be 16 char hex string
        assert isinstance(network_manager.node_id, str)
    
    def test_add_peer(self, network_manager, sample_node):
        """Test adding a peer to the network manager."""
        network_manager.add_peer(sample_node)
        assert sample_node.node_id in network_manager.peers
        assert network_manager.peers[sample_node.node_id] == sample_node
    
    def test_remove_peer(self, network_manager, sample_node):
        """Test removing a peer from the network manager."""
        network_manager.add_peer(sample_node)
        assert sample_node.node_id in network_manager.peers
        
        network_manager.remove_peer(sample_node.node_id)
        assert sample_node.node_id not in network_manager.peers
    
    def test_get_best_peers(self, network_manager):
        """Test getting best peers based on reputation."""
        # Add multiple nodes with different reputation scores
        nodes = [
            NetworkNode(
                node_id=f"node_{i}",
                ip_address=f"192.168.1.{i}",
                port=8080,
                node_type=NodeType.RELAY,
                public_key=b"test_key",
                bandwidth_capacity=1024,
                latency=float(i * 10),
                reputation_score=float(i) / 10.0
            )
            for i in range(1, 6)
        ]
        
        for node in nodes:
            network_manager.add_peer(node)
        
        best_peers = network_manager.get_best_peers(count=3)
        assert len(best_peers) == 3
        
        # Should be sorted by reputation (highest first)
        for i in range(len(best_peers) - 1):
            assert best_peers[i].reputation_score >= best_peers[i + 1].reputation_score


class TestNetworkNode:
    """Test cases for NetworkNode."""
    
    def test_node_creation(self, sample_node):
        """Test that network node is created correctly."""
        assert sample_node.node_id == "test_node_123"
        assert sample_node.ip_address == "192.168.1.100"
        assert sample_node.port == 8080
        assert sample_node.node_type == NodeType.RELAY
        assert sample_node.is_active is True
    
    def test_node_type_enum(self):
        """Test NodeType enum values."""
        assert NodeType.CLIENT.value == "client"
        assert NodeType.RELAY.value == "relay"
        assert NodeType.EXIT.value == "exit"
        assert NodeType.HYBRID.value == "hybrid"


@pytest.mark.asyncio
class TestNetworkManagerAsync:
    """Async test cases for NetworkManager."""
    
    async def test_connect_to_peer_invalid_host(self, network_manager):
        """Test connection to invalid host returns None."""
        result = await network_manager.connect_to_peer("invalid.host", 9999)
        assert result is None
    
    async def test_stop(self, network_manager):
        """Test stopping the network manager."""
        # This should not raise any exceptions
        await network_manager.stop()
        assert len(network_manager.active_connections) == 0

