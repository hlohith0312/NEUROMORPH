"""
Feature Extractor Module

Analyzes packet characteristics to build state representations for the DRL agent.
Maintains a sliding window of recent packets and extracts temporal and structural features.
"""

import numpy as np
import logging
from collections import deque
from typing import Dict, List, Optional
import time


class FeatureExtractor:
    """
    Extracts features from network packets for DRL agent state representation.
    
    Maintains a sliding window of packet metadata and computes features
    that mirror those used by Whisper Leak adversaries.
    """
    
    def __init__(self, config: dict):
        """
        Initialize feature extractor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Sliding window configuration
        self.window_size = config.get('morphing', {}).get('window_size', 10)
        
        # Packet history
        self.packet_window = deque(maxlen=self.window_size)
        
        # Feature dimensions
        self.features_per_packet = 5  # size, inter_arrival, ttl, flags_encoded, direction
        self.state_dim = self.window_size * self.features_per_packet
        
        # Normalization parameters (learned from baseline data)
        self.feature_stats = {
            'size_mean': 500.0,
            'size_std': 300.0,
            'time_mean': 0.05,
            'time_std': 0.03,
            'ttl_mean': 64.0,
            'ttl_std': 32.0,
        }
        
        # Last packet timestamp for inter-arrival time
        self.last_timestamp: Optional[float] = None
        
        self.logger.info(f"Feature Extractor initialized with window size: {self.window_size}")
    
    def extract_features(self, packet_data: dict) -> np.ndarray:
        """
        Extract features from a packet and update sliding window.
        
        Args:
            packet_data: Dictionary containing packet and metadata
            
        Returns:
            Feature vector representing current state
        """
        packet = packet_data['packet']
        timestamp = packet_data.get('timestamp', time.time())
        
        # Calculate inter-arrival time
        if self.last_timestamp is not None:
            inter_arrival = timestamp - self.last_timestamp
        else:
            inter_arrival = 0.0
        self.last_timestamp = timestamp
        
        # Extract raw features
        features = {
            'size': packet_data.get('size', 0),
            'inter_arrival': inter_arrival,
            'ttl': self._extract_ttl(packet),
            'flags': self._extract_tcp_flags_encoded(packet),
            'direction': self._extract_direction(packet),
        }
        
        # Add to sliding window
        self.packet_window.append(features)
        
        # Build state vector
        state = self._build_state_vector()
        
        return state
    
    def _extract_ttl(self, packet) -> int:
        """
        Extract IP Time-to-Live value.
        
        Args:
            packet: PyDivert packet object
            
        Returns:
            TTL value
        """
        if hasattr(packet, 'ttl') and packet.ttl is not None:
            return packet.ttl
        elif hasattr(packet, 'ipv4') and packet.ipv4 is not None and hasattr(packet.ipv4, 'ttl'):
            return packet.ipv4.ttl
        return 64  # Default
    
    def _extract_tcp_flags_encoded(self, packet) -> int:
        """
        Extract and encode TCP flags as integer.
        
        Encoding: SYN=1, ACK=2, FIN=4, RST=8, PSH=16
        
        Args:
            packet: PyDivert packet object
            
        Returns:
            Encoded flags value
        """
        if not hasattr(packet, 'tcp'):
            return 0
        
        tcp = packet.tcp
        flags = 0
        
        if hasattr(tcp, 'syn') and tcp.syn:
            flags |= 1
        if hasattr(tcp, 'ack') and tcp.ack:
            flags |= 2
        if hasattr(tcp, 'fin') and tcp.fin:
            flags |= 4
        if hasattr(tcp, 'rst') and tcp.rst:
            flags |= 8
        if hasattr(tcp, 'psh') and tcp.psh:
            flags |= 16
        
        return flags
    
    def _extract_direction(self, packet) -> int:
        """
        Determine packet direction (outbound=0, inbound=1).
        
        Args:
            packet: PyDivert packet object
            
        Returns:
            Direction indicator
        """
        # Simple heuristic: check if it's an outbound packet
        # In WinDivert, outbound packets typically have certain characteristics
        if hasattr(packet, 'is_outbound'):
            return 0 if packet.is_outbound else 1
        
        # Fallback: check port numbers (client typically uses high ports)
        if hasattr(packet, 'tcp'):
            if hasattr(packet.tcp, 'src_port') and packet.tcp.src_port > 1024:
                return 0  # Likely outbound
        
        return 1  # Assume inbound
    
    def _build_state_vector(self) -> np.ndarray:
        """
        Build normalized state vector from sliding window.
        
        Returns:
            Normalized feature vector
        """
        if len(self.packet_window) == 0:
            return np.zeros(self.state_dim, dtype=np.float32)
        
        # Collect features from window
        state_list = []
        
        for packet_features in self.packet_window:
            # Normalize each feature
            normalized = [
                self._normalize(packet_features['size'], 'size'),
                self._normalize(packet_features['inter_arrival'], 'time'),
                self._normalize(packet_features['ttl'], 'ttl'),
                packet_features['flags'] / 31.0,  # Max flags value is 31
                packet_features['direction'],  # Already 0 or 1
            ]
            state_list.extend(normalized)
        
        # Pad if window not full
        while len(state_list) < self.state_dim:
            state_list.append(0.0)
        
        return np.array(state_list, dtype=np.float32)
    
    def _normalize(self, value: float, feature_type: str) -> float:
        """
        Normalize feature value using z-score normalization.
        
        Args:
            value: Raw feature value
            feature_type: Type of feature ('size', 'time', 'ttl')
            
        Returns:
            Normalized value
        """
        mean = self.feature_stats.get(f'{feature_type}_mean', 0.0)
        std = self.feature_stats.get(f'{feature_type}_std', 1.0)
        
        if std == 0:
            return 0.0
        
        return (value - mean) / std
    
    def update_normalization_stats(self, baseline_data: List[Dict]):
        """
        Update normalization statistics from baseline data.
        
        Args:
            baseline_data: List of packet feature dictionaries
        """
        if not baseline_data:
            return
        
        # Calculate statistics
        sizes = [p['size'] for p in baseline_data if 'size' in p]
        times = [p.get('inter_arrival', 0) for p in baseline_data]
        ttls = [p.get('ttl', 64) for p in baseline_data]
        
        if sizes:
            self.feature_stats['size_mean'] = np.mean(sizes)
            self.feature_stats['size_std'] = np.std(sizes) + 1e-6
        
        if times:
            self.feature_stats['time_mean'] = np.mean(times)
            self.feature_stats['time_std'] = np.std(times) + 1e-6
        
        if ttls:
            self.feature_stats['ttl_mean'] = np.mean(ttls)
            self.feature_stats['ttl_std'] = np.std(ttls) + 1e-6
        
        self.logger.info(f"Updated normalization stats: {self.feature_stats}")
    
    def get_state_dim(self) -> int:
        """
        Get the dimensionality of the state vector.
        
        Returns:
            State dimension
        """
        return self.state_dim
    
    def reset(self):
        """Reset the sliding window and timestamp."""
        self.packet_window.clear()
        self.last_timestamp = None
    
    def get_window_summary(self) -> Dict:
        """
        Get summary statistics of current window.
        
        Returns:
            Dictionary with window statistics
        """
        if len(self.packet_window) == 0:
            return {}
        
        sizes = [p['size'] for p in self.packet_window]
        times = [p['inter_arrival'] for p in self.packet_window]
        
        return {
            'window_size': len(self.packet_window),
            'avg_packet_size': np.mean(sizes),
            'std_packet_size': np.std(sizes),
            'avg_inter_arrival': np.mean(times),
            'total_bytes': sum(sizes),
        }


class SequenceFeatureExtractor(FeatureExtractor):
    """
    Extended feature extractor for sequence-based analysis.
    
    Computes additional features for adversarial classifier evaluation.
    """
    
    def __init__(self, config: dict):
        """Initialize sequence feature extractor."""
        super().__init__(config)
        
        # Extended window for sequence analysis
        self.extended_window = deque(maxlen=50)
    
    def extract_sequence_features(self, packet_data: dict) -> Dict:
        """
        Extract sequence-level features for adversarial analysis.
        
        Args:
            packet_data: Packet information
            
        Returns:
            Dictionary of sequence features
        """
        # Extract basic features
        state = self.extract_features(packet_data)
        
        # Add to extended window
        self.extended_window.append(packet_data)
        
        # Compute sequence statistics
        if len(self.extended_window) < 5:
            return {'state': state, 'sequence_features': {}}
        
        # Extract sizes
        sizes = [p.get('size', 0) for p in self.extended_window]
        
        # Compute statistical features
        sequence_features = {
            'size_mean': np.mean(sizes),
            'size_std': np.std(sizes),
            'size_min': np.min(sizes),
            'size_max': np.max(sizes),
            'size_median': np.median(sizes),
            'size_range': np.max(sizes) - np.min(sizes),
            'burst_count': self._count_bursts(sizes),
            'entropy': self._compute_entropy(sizes),
        }
        
        return {
            'state': state,
            'sequence_features': sequence_features
        }
    
    def _count_bursts(self, sizes: List[int], threshold: int = 100) -> int:
        """
        Count number of bursts in size sequence.
        
        Args:
            sizes: List of packet sizes
            threshold: Minimum size to consider a burst
            
        Returns:
            Number of bursts
        """
        bursts = 0
        in_burst = False
        
        for size in sizes:
            if size > threshold:
                if not in_burst:
                    bursts += 1
                    in_burst = True
            else:
                in_burst = False
        
        return bursts
    
    def _compute_entropy(self, sizes: List[int]) -> float:
        """
        Compute Shannon entropy of size distribution.
        
        Args:
            sizes: List of packet sizes
            
        Returns:
            Entropy value
        """
        if not sizes:
            return 0.0
        
        # Bin sizes into buckets
        bins = 10
        hist, _ = np.histogram(sizes, bins=bins)
        
        # Normalize to probabilities
        probs = hist / np.sum(hist)
        
        # Remove zeros
        probs = probs[probs > 0]
        
        # Compute entropy
        entropy = -np.sum(probs * np.log2(probs))
        
        return entropy
