"""
NeuroMorph Logger - Thread-safe JSON Event Logger
Logs packet processing events to a JSONL file for real-time dashboard consumption
"""

import json
import time
import threading
import os
from pathlib import Path

# Thread-safe lock for file writes
_log_lock = threading.Lock()

# Log file path
LOG_FILE = Path("logs/neuromorph_dashboard.jsonl")

# Ensure logs directory exists
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

def log_packet_event(llm, original_size, morphed_size, action_id, action_name, adversary_accuracy):
    """
    Log a single packet processing event to the dashboard JSONL file.
    
    This function is:
    - Thread-safe (uses lock)
    - Non-blocking (fast write)
    - Fail-safe (handles errors silently)
    
    Args:
        llm (str): LLM service name (e.g., "ChatGPT", "Claude")
        original_size (int): Original packet size in bytes
        morphed_size (int): Morphed packet size in bytes
        action_id (int): Action ID (0-12)
        action_name (str): Human-readable action name
        adversary_accuracy (float): Current adversary accuracy (0.0 - 1.0)
    """
    try:
        # Calculate bytes added
        bytes_padded = max(0, morphed_size - original_size)
        
        # Create event object
        event = {
            "timestamp": time.time(),
            "llm": llm,
            "original_size": original_size,
            "morphed_size": morphed_size,
            "action_id": action_id,
            "action_name": action_name,
            "bytes_padded": bytes_padded,
            "adversary_accuracy": adversary_accuracy
        }
        
        # Thread-safe write
        with _log_lock:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event) + '\n')
                f.flush()  # Ensure immediate write
    
    except Exception as e:
        # Fail silently - don't disrupt packet processing
        pass


def clear_log():
    """
    Clear the dashboard log file (useful for testing or reset).
    Call this at the start of main.py if you want a fresh log.
    """
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


# ==============================================================================
# HOW TO USE IN main.py:
# ==============================================================================
# 
# 1. Import at the top of main.py:
#    from neuromorph_logger import log_packet_event, clear_log
#
# 2. Optional - Clear log at startup (in main() function):
#    clear_log()
#
# 3. After each packet is morphed, call:
#    log_packet_event(
#        llm="ChatGPT",                    # LLM service name
#        original_size=packet_data['size'],
#        morphed_size=result['morphed_size'],
#        action_id=action,                  # 0-12
#        action_name=ACTION_NAMES[action],
#        adversary_accuracy=current_accuracy  # 0.0-1.0
#    )
#
# Example integration in packet processing loop:
# 
#   for packet in captured_packets:
#       # Extract LLM from packet analysis
#       llm = identify_llm_service(packet)
#       
#       # Get original size
#       original_size = len(packet.payload)
#       
#       # Apply DRL action
#       action = agent.select_action(state)
#       morphed_packet = apply_action(packet, action)
#       
#       # Get morphed size
#       morphed_size = len(morphed_packet.payload)
#       
#       # Calculate current adversary accuracy
#       adversary_accuracy = evaluate_defense(morphed_packet)
#       
#       # Log the event (non-blocking, thread-safe)
#       log_packet_event(
#           llm=llm,
#           original_size=original_size,
#           morphed_size=morphed_size,
#           action_id=action,
#           action_name=ACTION_NAMES[action],
#           adversary_accuracy=adversary_accuracy
#       )
#
# ACTION_NAMES dictionary (define in main.py):
#
# ACTION_NAMES = {
#     0: "Pass Through",
#     1: "Temporal Jitter",
#     2: "Payload Padding",
#     3: "TCP Segmentation",
#     4: "Constant Size",
#     5: "Fixed Rate Clock",
#     6: "Cover Traffic",
#     7: "Video Mimicry",
#     8: "DNS Mimicry",
#     9: "Inverse Decoy",
#     10: "Max Entropy",
#     11: "Full Ensemble",
#     12: "Perfect Mimicry"
# }
#
# ==============================================================================
