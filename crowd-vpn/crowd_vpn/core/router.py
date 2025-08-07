"""Traffic routing and forwarding for Crowd VPN."""

import asyncio
import logging
import random
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from .network import NetworkNode, NodeType


class RoutingAlgorithm(Enum):
    """Available routing algorithms."""
    RANDOM = "random"
    SHORTEST_PATH = "shortest_path"
    LOAD_BALANCED = "load_balanced"
    REPUTATION_BASED = "reputation_based"


@dataclass
class Route:
    """Represents a routing path through the network."""
    route_id: str
    source_node: str
    destination: str  # IP or domain
    hops: List[NetworkNode]
    total_latency: float
    bandwidth_limit: int
    created_time: float
    is_active: bool = True


@dataclass
class TrafficPacket:
    """Represents a packet of traffic to be routed."""
    packet_id: str
    route_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    data: bytes
    hop_count: int = 0
    max_hops: int = 5


class TrafficRouter:
    """Handles traffic routing through the crowd VPN network."""
    
    def __init__(self, network_manager, algorithm: RoutingAlgorithm = RoutingAlgorithm.REPUTATION_BASED):
        self.network_manager = network_manager
        self.routing_algorithm = algorithm
        self.active_routes: Dict[str, Route] = {}
        self.traffic_stats: Dict[str, dict] = {}
        self.logger = logging.getLogger(__name__)
        
    def create_route(self, destination: str, required_bandwidth: int = 1024) -> Optional[Route]:
        """Create a new route to the destination."""
        available_nodes = self._get_available_nodes()
        
        if not available_nodes:
            self.logger.warning("No available nodes for routing")
            return None
        
        # Select nodes based on the routing algorithm
        selected_nodes = self._select_route_nodes(available_nodes, destination, required_bandwidth)
        
        if not selected_nodes:
            self.logger.warning(f"Could not create route to {destination}")
            return None
        
        route = Route(
            route_id=self._generate_route_id(),
            source_node=self.network_manager.node_id,
            destination=destination,
            hops=selected_nodes,
            total_latency=sum(node.latency for node in selected_nodes),
            bandwidth_limit=min(node.bandwidth_capacity for node in selected_nodes),
            created_time=asyncio.get_event_loop().time()
        )
        
        self.active_routes[route.route_id] = route
        self.logger.info(f"Created route {route.route_id} to {destination} with {len(selected_nodes)} hops")
        
        return route
    
    def _get_available_nodes(self) -> List[NetworkNode]:
        """Get list of available nodes for routing."""
        return [
            node for node in self.network_manager.peers.values()
            if node.is_active and node.node_type in [NodeType.RELAY, NodeType.EXIT, NodeType.HYBRID]
        ]
    
    def _select_route_nodes(self, available_nodes: List[NetworkNode], destination: str, 
                           required_bandwidth: int) -> List[NetworkNode]:
        """Select nodes for the route based on the routing algorithm."""
        
        # Filter nodes that meet bandwidth requirements
        suitable_nodes = [
            node for node in available_nodes
            if node.bandwidth_capacity >= required_bandwidth
        ]
        
        if not suitable_nodes:
            return []
        
        if self.routing_algorithm == RoutingAlgorithm.RANDOM:
            return self._random_selection(suitable_nodes)
        elif self.routing_algorithm == RoutingAlgorithm.REPUTATION_BASED:
            return self._reputation_based_selection(suitable_nodes)
        elif self.routing_algorithm == RoutingAlgorithm.LOAD_BALANCED:
            return self._load_balanced_selection(suitable_nodes)
        else:
            return self._random_selection(suitable_nodes)
    
    def _random_selection(self, nodes: List[NetworkNode]) -> List[NetworkNode]:
        """Random node selection."""
        num_hops = min(3, len(nodes))  # Use up to 3 hops
        return random.sample(nodes, num_hops)
    
    def _reputation_based_selection(self, nodes: List[NetworkNode]) -> List[NetworkNode]:
        """Select nodes based on reputation scores."""
        # Sort by reputation score (highest first)
        sorted_nodes = sorted(nodes, key=lambda n: n.reputation_score, reverse=True)
        
        # Select top nodes with some randomization to avoid overloading best nodes
        num_hops = min(3, len(sorted_nodes))
        top_candidates = sorted_nodes[:min(6, len(sorted_nodes))]  # Top 6 candidates
        
        selected = []
        for i in range(num_hops):
            if top_candidates:
                # Higher probability for better nodes, but still some randomness
                weights = [node.reputation_score ** 2 for node in top_candidates]
                chosen = random.choices(top_candidates, weights=weights)[0]
                selected.append(chosen)
                top_candidates.remove(chosen)
        
        return selected
    
    def _load_balanced_selection(self, nodes: List[NetworkNode]) -> List[NetworkNode]:
        """Select nodes based on current load balancing."""
        # For now, use reputation-based with load consideration
        # In a full implementation, we'd track current load per node
        return self._reputation_based_selection(nodes)
    
    async def route_packet(self, packet: TrafficPacket) -> bool:
        """Route a traffic packet through the network."""
        route = self.active_routes.get(packet.route_id)
        if not route or not route.is_active:
            self.logger.error(f"No active route found for packet {packet.packet_id}")
            return False
        
        if packet.hop_count >= packet.max_hops:
            self.logger.warning(f"Packet {packet.packet_id} exceeded max hops")
            return False
        
        try:
            # Get the next hop in the route
            current_hop_index = packet.hop_count
            if current_hop_index >= len(route.hops):
                # Reached the end of the route, forward to destination
                return await self._forward_to_destination(packet)
            
            next_hop = route.hops[current_hop_index]
            
            # Forward packet to next hop
            success = await self._forward_to_node(packet, next_hop)
            
            if success:
                packet.hop_count += 1
                self._update_traffic_stats(route.route_id, len(packet.data))
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error routing packet {packet.packet_id}: {e}")
            return False
    
    async def _forward_to_node(self, packet: TrafficPacket, node: NetworkNode) -> bool:
        """Forward a packet to a specific node."""
        try:
            # Get connection to the node
            writer = self.network_manager.active_connections.get(node.node_id)
            if not writer:
                # Try to establish connection if not exists
                connection_id = await self.network_manager.connect_to_peer(node.ip_address, node.port)
                if not connection_id:
                    return False
                writer = self.network_manager.active_connections.get(node.node_id)
            
            if writer:
                # Create forwarding message
                import json
                forward_message = {
                    'type': 'forward_packet',
                    'packet_id': packet.packet_id,
                    'route_id': packet.route_id,
                    'destination_ip': packet.destination_ip,
                    'destination_port': packet.destination_port,
                    'hop_count': packet.hop_count,
                    'data': packet.data.hex()  # Convert bytes to hex for JSON
                }
                
                message = json.dumps(forward_message).encode() + b'\n'
                writer.write(message)
                await writer.drain()
                
                return True
            
        except Exception as e:
            self.logger.error(f"Error forwarding packet to node {node.node_id}: {e}")
        
        return False
    
    async def _forward_to_destination(self, packet: TrafficPacket) -> bool:
        """Forward packet to final destination (exit node functionality)."""
        try:
            # This would implement the actual internet connection
            # For now, just log the action
            self.logger.info(f"Forwarding packet {packet.packet_id} to final destination {packet.destination_ip}:{packet.destination_port}")
            
            # In a real implementation, this would:
            # 1. Create a connection to the destination
            # 2. Send the packet data
            # 3. Receive response and route back through the network
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error forwarding to destination: {e}")
            return False
    
    def _generate_route_id(self) -> str:
        """Generate a unique route ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def _update_traffic_stats(self, route_id: str, bytes_transferred: int):
        """Update traffic statistics for a route."""
        if route_id not in self.traffic_stats:
            self.traffic_stats[route_id] = {
                'bytes_transferred': 0,
                'packet_count': 0,
                'last_activity': asyncio.get_event_loop().time()
            }
        
        self.traffic_stats[route_id]['bytes_transferred'] += bytes_transferred
        self.traffic_stats[route_id]['packet_count'] += 1
        self.traffic_stats[route_id]['last_activity'] = asyncio.get_event_loop().time()
    
    def get_route_stats(self, route_id: str) -> Optional[dict]:
        """Get statistics for a specific route."""
        return self.traffic_stats.get(route_id)
    
    def cleanup_inactive_routes(self, max_age_seconds: int = 300):
        """Clean up inactive routes older than max_age_seconds."""
        current_time = asyncio.get_event_loop().time()
        inactive_routes = []
        
        for route_id, route in self.active_routes.items():
            if current_time - route.created_time > max_age_seconds:
                inactive_routes.append(route_id)
        
        for route_id in inactive_routes:
            del self.active_routes[route_id]
            if route_id in self.traffic_stats:
                del self.traffic_stats[route_id]
            self.logger.info(f"Cleaned up inactive route {route_id}")

