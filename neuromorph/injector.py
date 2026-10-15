"""
Packet Injector Module

Executes packet modifications and re-injects packets into the network stack
with proper checksum recalculation and TCP state management.
"""

import logging
from typing import List, Optional, Dict
import time

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False


class PacketInjector:
    """
    Handles packet modification and re-injection with checksum management.
    
    Applies morphing actions and ensures modified packets remain valid
    and routable through proper checksum recalculation.
    """
    
    def __init__(self, config: dict):
        """
        Initialize packet injector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Performance settings
        perf_config = config.get('performance', {})
        self.checksum_offload = perf_config.get('checksum_offload', True)
        
        # Statistics
        self.stats = {
            'packets_injected': 0,
            'packets_modified': 0,
            'checksum_recalculations': 0,
            'bytes_added': 0,
            'segmentation_count': 0,
        }
        
        self.logger.info("Packet Injector initialized")
    
    def inject_packet(self, packet, divert_handle) -> bool:
        """
        Inject a single packet back into the network stack.
        
        Args:
            packet: PyDivert packet object
            divert_handle: Active WinDivert handle
            
        Returns:
            True if injection successful
        """
        if not PYDIVERT_AVAILABLE:
            return False
        
        try:
            # Recalculate checksums if needed
            if self.checksum_offload:
                packet.recalculate_checksums()
                self.stats['checksum_recalculations'] += 1
            
            # Send packet
            divert_handle.send(packet)
            self.stats['packets_injected'] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to inject packet: {e}")
            return False
    
    def inject_modified_packet(self, packet_data: Dict, divert_handle) -> bool:
        """
        Inject a modified packet with proper handling.
        
        Args:
            packet_data: Dictionary containing packet and modification info
            divert_handle: Active WinDivert handle
            
        Returns:
            True if injection successful
        """
        packet = packet_data.get('packet')
        
        if packet is None:
            self.logger.warning("No packet in packet_data")
            return False
        
        # Handle segmented packets
        if 'segments' in packet_data:
            return self._inject_segments(packet_data['segments'], divert_handle)
        
        # Update statistics
        if 'padding_added' in packet_data:
            self.stats['bytes_added'] += packet_data['padding_added']
            self.stats['packets_modified'] += 1
        
        # Inject single packet
        return self.inject_packet(packet, divert_handle)
    
    def _inject_segments(self, segments: List, divert_handle) -> bool:
        """
        Inject multiple TCP segments.
        
        Args:
            segments: List of packet segments
            divert_handle: Active WinDivert handle
            
        Returns:
            True if all segments injected successfully
        """
        success = True
        
        for i, segment in enumerate(segments):
            if not self.inject_packet(segment, divert_handle):
                self.logger.warning(f"Failed to inject segment {i+1}/{len(segments)}")
                success = False
            
            # Small delay between segments to avoid overwhelming the stack
            if i < len(segments) - 1:
                time.sleep(0.0001)  # 100 microseconds
        
        self.stats['segmentation_count'] += 1
        self.stats['packets_modified'] += 1
        
        return success
    
    def prepare_padding_injection(self, packet, padding_size: int):
        """
        Prepare a packet for padding injection.
        
        Updates packet structure to accommodate additional padding.
        
        Args:
            packet: PyDivert packet object
            padding_size: Number of bytes to add
            
        Returns:
            Modified packet
        """
        if not PYDIVERT_AVAILABLE or not hasattr(packet, 'ipv4') or packet.ipv4 is None:
            return packet
        
        try:
            # Update IP total length
            if hasattr(packet, 'ipv4') and packet.ipv4 is not None and hasattr(packet.ipv4, 'packet_len'):
                packet.ipv4.packet_len += padding_size
            
            # Update TCP window size if needed
            if hasattr(packet, 'tcp') and packet.tcp is not None and hasattr(packet.tcp, 'window_size'):
                # Maintain reasonable window size
                pass
            
            return packet
            
        except Exception as e:
            self.logger.error(f"Error preparing padding: {e}")
            return packet
    
    def validate_packet(self, packet) -> bool:
        """
        Validate packet structure before injection.
        
        Args:
            packet: PyDivert packet object
            
        Returns:
            True if packet is valid
        """
        if not PYDIVERT_AVAILABLE or packet is None:
            return False
        
        try:
            # Check basic structure
            if not hasattr(packet, 'src_addr') or not hasattr(packet, 'dst_addr'):
                return False
            
            # Check TCP structure if TCP packet
            if hasattr(packet, 'tcp') and packet.tcp is not None:
                if not hasattr(packet.tcp, 'src_port') or not hasattr(packet.tcp, 'dst_port'):
                    return False
            
            # Check payload isn't excessively large
            if packet.payload and len(packet.payload) > 65535:
                self.logger.warning("Payload too large")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Packet validation error: {e}")
            return False
    
    def inject_with_retry(self, packet, divert_handle, max_retries: int = 3) -> bool:
        """
        Inject packet with retry logic.
        
        Args:
            packet: PyDivert packet object
            divert_handle: Active WinDivert handle
            max_retries: Maximum number of retry attempts
            
        Returns:
            True if injection successful
        """
        for attempt in range(max_retries):
            if self.inject_packet(packet, divert_handle):
                return True
            
            self.logger.warning(f"Injection attempt {attempt + 1} failed, retrying...")
            time.sleep(0.001 * (attempt + 1))  # Exponential backoff
        
        self.logger.error(f"Failed to inject packet after {max_retries} attempts")
        return False
    
    def get_statistics(self) -> Dict:
        """
        Get injection statistics.
        
        Returns:
            Dictionary of statistics
        """
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset all statistics counters."""
        self.stats = {
            'packets_injected': 0,
            'packets_modified': 0,
            'checksum_recalculations': 0,
            'bytes_added': 0,
            'segmentation_count': 0,
        }


class MorphingCoordinator:
    """
    High-level coordinator that combines feature extraction,
    action selection, and packet injection.
    """
    
    def __init__(self, feature_extractor, morphing_engine, packet_injector, morphing_strategy):
        """
        Initialize coordinator.
        
        Args:
            feature_extractor: FeatureExtractor instance
            morphing_engine: DRLMorphingEngine instance
            packet_injector: PacketInjector instance
            morphing_strategy: MorphingStrategy instance
        """
        self.feature_extractor = feature_extractor
        self.morphing_engine = morphing_engine
        self.packet_injector = packet_injector
        self.morphing_strategy = morphing_strategy
        self.logger = logging.getLogger(__name__)
        
        # Performance tracking
        self.processing_times = []
        self.max_tracking = 1000
    
    async def process_packet(self, packet_data: Dict) -> Dict:
        """
        Process a packet through the complete morphing pipeline.
        
        Args:
            packet_data: Packet information dictionary
            
        Returns:
            Result dictionary with modified packet and action taken
        """
        start_time = time.time()
        
        try:
            # Extract features
            state = self.feature_extractor.extract_features(packet_data)
            
            # Select action
            action = self.morphing_engine.select_action(state, deterministic=False)
            
            # Apply morphing
            modified_data = await self.morphing_strategy.apply_action(action, packet_data)
            
            # Track processing time
            processing_time = (time.time() - start_time) * 1000  # milliseconds
            self.processing_times.append(processing_time)
            if len(self.processing_times) > self.max_tracking:
                self.processing_times.pop(0)
            
            # Calculate morphed size
            modified_pkt = modified_data.get('packet')
            if modified_pkt and hasattr(modified_pkt, 'payload') and modified_pkt.payload and len(modified_pkt.payload) > 0:
                morphed_size = len(modified_pkt.payload)
            elif 'perfect_mimicry_size' in modified_data:
                morphed_size = modified_data['perfect_mimicry_size']
            elif 'padding_added' in modified_data:
                morphed_size = packet_data.get('size', 0) + modified_data['padding_added']
            elif action in [4, 11, 12]:
                morphed_size = 1400
            elif action == 7:
                morphed_size = 1390
            elif action == 8:
                morphed_size = 60
            elif action == 9:
                morphed_size = 120
            else:
                morphed_size = packet_data.get('size', 0)

            return {
                'modified_packet': modified_data.get('packet'),
                'action': action,
                'processing_time_ms': processing_time,
                'state': state,
                'segments': modified_data.get('segments'),
                'morphed_size': morphed_size,
            }
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
            return {
                'modified_packet': packet_data.get('packet'),
                'action': 0,  # Pass through on error
                'error': str(e)
            }
    
    def get_performance_metrics(self) -> Dict:
        """
        Get performance metrics for the morphing pipeline.
        
        Returns:
            Dictionary of performance metrics
        """
        if not self.processing_times:
            return {}
        
        import numpy as np
        
        return {
            'mean_processing_time_ms': np.mean(self.processing_times),
            'p50_processing_time_ms': np.percentile(self.processing_times, 50),
            'p95_processing_time_ms': np.percentile(self.processing_times, 95),
            'p99_processing_time_ms': np.percentile(self.processing_times, 99),
            'max_processing_time_ms': np.max(self.processing_times),
        }
