"""
NeuroMorph Real-Time Desktop Dashboard
Professional UI displaying live packet morphing activity
"""

import tkinter as tk
from tkinter import font as tkfont
import json
import time
import threading
import os
from pathlib import Path
from collections import deque, Counter
import math

# Configuration
LOG_FILE = Path("logs/neuromorph_dashboard.jsonl")
CONTROL_FILE = Path("logs/control.json")
POLL_INTERVAL_MS = 500  # Poll every 500ms
ACTIVITY_TIMEOUT = 60.0  # Keep active for 60 seconds after traffic
MAX_LOG_LINES = 50  # Keep last 50 packets in scrolling log

# Action definitions
ACTIONS = {
    0: "Pass Through",
    1: "Temporal Jitter",
    2: "Payload Padding",
    3: "TCP Segmentation",
    4: "Constant Size",
    5: "Fixed Rate Clock",
    6: "Cover Traffic",
    7: "Video Mimicry",
    8: "DNS Mimicry",
    9: "Inverse Decoy",
    10: "Max Entropy",
    11: "Full Ensemble",
    12: "Perfect Mimicry",
    13: "Netflix Video Streaming"
}

# Action descriptions
ACTION_DESCRIPTIONS = {
    0: "No morphing applied",
    1: "Random delays: 0.5ms-5ms",
    2: "Padding: 10-500 bytes",
    3: "Split into 2-100B segments",
    4: "All packets → 1400B",
    5: "Fixed 10ms intervals",
    6: "1 dummy per 2 real packets",
    7: "Netflix video mimicry",
    8: "8 tiny 60B DNS fragments",
    9: "Opposite topic disguise",
    10: "Random 40-1500B",
    11: "Combined: 4+5+6+7",
    12: "Perfect: 1400B+10ms+dummies",
    13: "Netflix Video: Constant 1400B @ 10ms"
}

# LLM / AI services — every provider the system can detect
ALL_LLMS = [
    "ChatGPT", "Copilot", "Gemini", "Claude", "Perplexity",
    "Cohere", "Mistral", "HuggingFace",
    "Grok", "Meta AI", "DeepSeek", "Groq",
    "Character.AI", "Stability AI", "ElevenLabs", "Runway", "Pika",
    "Pi", "You.com", "Together AI", "Replicate", "Amazon AI",
    "Adobe Firefly", "Midjourney", "Suno", "Udio",
    "Qwen", "Kimi", "Jasper", "Copy.ai", "Notion AI",
    "Cursor", "Codeium", "Tabnine", "Writesonic", "Grammarly",
]

# Color scheme
COLOR_BG = "#000000"
COLOR_PANEL = "#0a0a0a"
COLOR_TEXT = "#00ff00"
COLOR_TEXT_DIM = "#004400"
COLOR_ACTIVE = "#00ff00"
COLOR_INACTIVE = "#333333"
COLOR_RED = "#ff0000"
COLOR_GREEN = "#00ff00"
COLOR_CYAN = "#00ffff"
COLOR_YELLOW = "#ffff00"
COLOR_ORANGE = "#ff8800"


class NeuroMorphDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("NeuroMorph — Active Deception Engine")
        self.root.geometry("1280x720")
        self.root.configure(bg=COLOR_BG)
        self.root.resizable(False, False)
        
        # State
        self.file_position = 0
        self.is_active = False
        self.action_13_active = False
        self.last_packet_time = 0
        self.start_time = None
        self.current_action = 0
        self.current_adversary_accuracy = 0.0
        self.current_llm = ""
        
        # Statistics
        self.total_packets = 0
        self.total_morphed = 0
        self.total_bytes_padded = 0
        self.active_llms = set()
        self.recent_packets = deque(maxlen=MAX_LOG_LINES)
        
        # Fonts
        self.font_header = tkfont.Font(family="Courier New", size=16, weight="bold")
        self.font_title = tkfont.Font(family="Courier New", size=12, weight="bold")
        self.font_normal = tkfont.Font(family="Courier New", size=10)
        self.font_small = tkfont.Font(family="Courier New", size=8)
        self.font_large = tkfont.Font(family="Courier New", size=24, weight="bold")
        
        # Build UI
        self.build_ui()
        
        # Start polling
        self.poll_log_file()
        self.update_status()
        self.update_uptime()
    
    def build_ui(self):
        """Build the complete dashboard UI"""
        
        # Header
        self.build_header()
        
        # Main content frame
        content_frame = tk.Frame(self.root, bg=COLOR_BG)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - DRL Actions
        left_panel = tk.Frame(content_frame, bg=COLOR_PANEL, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        left_panel.pack_propagate(False)
        self.build_left_panel(left_panel)
        
        # Center panel - Packet Stream
        center_panel = tk.Frame(content_frame, bg=COLOR_PANEL, width=460)
        center_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.build_center_panel(center_panel)
        
        # Right panel - Deception Control
        right_panel = tk.Frame(content_frame, bg=COLOR_PANEL, width=320)
        right_panel.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        right_panel.pack_propagate(False)
        self.build_right_panel(right_panel)
        
        # Bottom stats bar
        self.build_bottom_bar()
    
    def build_header(self):
        """Build top header bar"""
        header = tk.Frame(self.root, bg=COLOR_PANEL, height=60)
        header.pack(fill=tk.X, padx=10, pady=10)
        header.pack_propagate(False)
        
        # Title
        title = tk.Label(
            header,
            text="NeuroMorph — Active Deception Engine",
            font=self.font_header,
            fg=COLOR_CYAN,
            bg=COLOR_PANEL
        )
        title.pack(side=tk.LEFT, padx=20)
        
        # Status indicator
        self.status_frame = tk.Frame(header, bg=COLOR_PANEL)
        self.status_frame.pack(side=tk.LEFT, padx=20)
        
        self.status_dot = tk.Canvas(self.status_frame, width=20, height=20, bg=COLOR_PANEL, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=5)
        self.status_dot.create_oval(2, 2, 18, 18, fill=COLOR_INACTIVE, outline="")
        
        self.status_label = tk.Label(
            self.status_frame,
            text="WAITING FOR TRAFFIC...",
            font=self.font_title,
            fg=COLOR_INACTIVE,
            bg=COLOR_PANEL
        )
        self.status_label.pack(side=tk.LEFT)
        
        # Uptime
        self.uptime_label = tk.Label(
            header,
            text="Uptime: 00:00:00",
            font=self.font_normal,
            fg=COLOR_TEXT_DIM,
            bg=COLOR_PANEL
        )
        self.uptime_label.pack(side=tk.RIGHT, padx=20)
    
    def build_left_panel(self, parent):
        """Build left panel - DRL Actions"""
        title = tk.Label(
            parent,
            text="DRL AGENT DECISION",
            font=self.font_title,
            fg=COLOR_CYAN,
            bg=COLOR_PANEL
        )
        title.pack(pady=10)
        
        # Scrollable action list
        canvas = tk.Canvas(parent, bg=COLOR_PANEL, highlightthickness=0)
        scrollbar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLOR_PANEL)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create action labels
        self.action_labels = {}
        for action_id, action_name in ACTIONS.items():
            frame = tk.Frame(scrollable_frame, bg=COLOR_PANEL)
            frame.pack(fill=tk.X, padx=10, pady=3)
            
            label = tk.Label(
                frame,
                text=f"[{action_id:2d}] {action_name}",
                font=self.font_normal,
                fg=COLOR_TEXT_DIM,
                bg=COLOR_PANEL,
                anchor="w"
            )
            label.pack(side=tk.LEFT)
            
            badge = tk.Label(
                frame,
                text="",
                font=self.font_small,
                fg=COLOR_ACTIVE,
                bg=COLOR_PANEL
            )
            badge.pack(side=tk.RIGHT)
            
            self.action_labels[action_id] = (label, badge)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Info section
        info_frame = tk.Frame(parent, bg=COLOR_PANEL)
        info_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=10)
        
        self.state_info = tk.Label(
            info_frame,
            text="State Vector: 80 features\nWindow: 16 packets",
            font=self.font_small,
            fg=COLOR_TEXT_DIM,
            bg=COLOR_PANEL,
            justify=tk.LEFT
        )
        self.state_info.pack(padx=10)
        
        self.last_action_label = tk.Label(
            info_frame,
            text="Last action: None",
            font=self.font_small,
            fg=COLOR_TEXT,
            bg=COLOR_PANEL,
            justify=tk.LEFT
        )
        self.last_action_label.pack(padx=10, pady=5)
    
    def build_center_panel(self, parent):
        """Build center panel - Live Packet Stream"""
        title = tk.Label(
            parent,
            text="LIVE PACKET STREAM",
            font=self.font_title,
            fg=COLOR_CYAN,
            bg=COLOR_PANEL
        )
        title.pack(pady=10)
        
        # Scrollable packet log
        log_frame = tk.Frame(parent, bg=COLOR_PANEL)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        scrollbar = tk.Scrollbar(log_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_log = tk.Text(
            log_frame,
            font=self.font_small,
            bg="#050505",
            fg=COLOR_TEXT,
            insertbackground=COLOR_TEXT,
            yscrollcommand=scrollbar.set,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.packet_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.packet_log.yview)
        
        # Configure tags for colored text
        self.packet_log.tag_config("timestamp", foreground=COLOR_TEXT_DIM)
        self.packet_log.tag_config("llm", foreground=COLOR_CYAN)
        self.packet_log.tag_config("original", foreground=COLOR_RED)
        self.packet_log.tag_config("morphed", foreground=COLOR_GREEN)
        self.packet_log.tag_config("action", foreground=COLOR_YELLOW)
    
    def build_right_panel(self, parent):
        """Build right panel - Action 13 Netflix Video Streaming Control"""
        title = tk.Label(
            parent,
            text="DECEPTION CONTROL",
            font=self.font_title,
            fg=COLOR_CYAN,
            bg=COLOR_PANEL
        )
        title.pack(pady=10)

        # Big prominent Action 13 Button
        btn_frame = tk.Frame(parent, bg=COLOR_PANEL)
        btn_frame.pack(fill=tk.X, padx=15, pady=10)

        self.action_13_btn = tk.Button(
            btn_frame,
            text="🎬 ACTIVATE ACTION 13\n[ NETFLIX VIDEO STREAMING ]",
            font=self.font_title,
            bg="#1c1c1c",
            fg=COLOR_GREEN,
            activebackground=COLOR_GREEN,
            activeforeground="#000000",
            relief=tk.RAISED,
            bd=3,
            command=self.toggle_action_13,
            cursor="hand2",
            padx=10,
            pady=15
        )
        self.action_13_btn.pack(fill=tk.X)

        # Profile Specification Card
        card = tk.LabelFrame(
            parent,
            text=" ACTIVE DECEPTION PROFILE ",
            font=self.font_small,
            fg=COLOR_CYAN,
            bg=COLOR_PANEL,
            padx=10,
            pady=8
        )
        card.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.mode_status_label = tk.Label(
            card,
            text="Mode: Adaptive DRL Engine",
            font=self.font_normal,
            fg=COLOR_TEXT_DIM,
            bg=COLOR_PANEL,
            anchor="w"
        )
        self.mode_status_label.pack(fill=tk.X, pady=4)

        specs_container = tk.Frame(card, bg=COLOR_PANEL)
        specs_container.pack(fill=tk.BOTH, expand=True, pady=4, padx=5)

        specs = [
            ("Camouflage:", "Netflix 1080p Video"),
            ("Payload:", "Fixed 1400B MTU"),
            ("Pacing Clock:", "10.0 ms (100 PPS)"),
            ("Entropy:", "Flat (Zero Variance)"),
            ("Traffic View:", "Encrypted Video Stream"),
        ]

        for i, (k, v) in enumerate(specs):
            lbl_k = tk.Label(
                specs_container,
                text=k,
                font=self.font_small,
                fg=COLOR_TEXT_DIM,
                bg=COLOR_PANEL,
                anchor="w"
            )
            lbl_k.grid(row=i, column=0, sticky="w", pady=4, padx=(2, 5))

            lbl_v = tk.Label(
                specs_container,
                text=v,
                font=self.font_small,
                fg=COLOR_GREEN,
                bg=COLOR_PANEL,
                anchor="e"
            )
            lbl_v.grid(row=i, column=1, sticky="e", pady=4)

        specs_container.columnconfigure(0, weight=1)
        specs_container.columnconfigure(1, weight=1)

        self.netflix_status_banner = tk.Label(
            card,
            text="Click button above to force ALL packets into Netflix Video Streaming.",
            font=self.font_small,
            fg=COLOR_YELLOW,
            bg=COLOR_PANEL,
            wraplength=270,
            justify=tk.CENTER
        )
        self.netflix_status_banner.pack(side=tk.BOTTOM, pady=8)

    def toggle_action_13(self):
        """Toggle Action 13 (Netflix Video Streaming) override"""
        self.action_13_active = not self.action_13_active
        if self.action_13_active:
            try:
                CONTROL_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(CONTROL_FILE, 'w', encoding='utf-8') as f:
                    json.dump({"force_action": 13, "action_name": "Netflix Video Streaming"}, f)
            except Exception:
                pass
            self.action_13_btn.config(
                text="✅ ACTION 13 ACTIVE\n[ NETFLIX STREAMING ON ]",
                bg=COLOR_GREEN,
                fg="#000000"
            )
            self.mode_status_label.config(
                text="Mode: FORCED NETFLIX (Action 13)",
                fg=COLOR_GREEN
            )
            self.netflix_status_banner.config(
                text="ALL outgoing packets are now morphed into Netflix Video Streaming!",
                fg=COLOR_GREEN
            )
            self.current_action = 13
            self.update_action_list()
        else:
            try:
                if CONTROL_FILE.exists():
                    CONTROL_FILE.unlink()
            except Exception:
                pass
            self.action_13_btn.config(
                text="🎬 ACTIVATE ACTION 13\n[ NETFLIX VIDEO STREAMING ]",
                bg="#1c1c1c",
                fg=COLOR_GREEN
            )
            self.mode_status_label.config(
                text="Mode: Adaptive DRL Engine",
                fg=COLOR_TEXT_DIM
            )
            self.netflix_status_banner.config(
                text="Click button above to force ALL packets into Netflix Video Streaming.",
                fg=COLOR_YELLOW
            )
    
    def build_bottom_bar(self):
        """Build bottom statistics bar"""
        bottom = tk.Frame(self.root, bg=COLOR_PANEL, height=50)
        bottom.pack(fill=tk.X, padx=10, pady=10, side=tk.BOTTOM)
        bottom.pack_propagate(False)
        
        # Stats grid
        stats_frame = tk.Frame(bottom, bg=COLOR_PANEL)
        stats_frame.pack(expand=True, pady=10)
        
        # Packet stats
        row1 = tk.Frame(stats_frame, bg=COLOR_PANEL)
        row1.pack()
        
        self.stat_intercepted = self.create_stat_label(row1, "Packets Intercepted:", "0")
        self.stat_morphed = self.create_stat_label(row1, "Packets Morphed:", "0")
        self.stat_padded = self.create_stat_label(row1, "Bytes Padded:", "0 B")
        self.llm_labels = {}
    
    def create_stat_label(self, parent, title, value):
        """Create a stat label pair"""
        frame = tk.Frame(parent, bg=COLOR_PANEL)
        frame.pack(side=tk.LEFT, padx=20)
        
        tk.Label(
            frame,
            text=title,
            font=self.font_small,
            fg=COLOR_TEXT_DIM,
            bg=COLOR_PANEL
        ).pack(side=tk.LEFT)
        
        value_label = tk.Label(
            frame,
            text=value,
            font=self.font_small,
            fg=COLOR_TEXT,
            bg=COLOR_PANEL
        )
        value_label.pack(side=tk.LEFT, padx=5)
        
        return value_label
    
    def poll_log_file(self):
        """Poll log file for new lines with batch UI updating"""
        try:
            if LOG_FILE.exists():
                file_size = LOG_FILE.stat().st_size
                # If file was truncated/cleared (e.g. main.py restarted), reset position to 0
                if file_size < self.file_position:
                    self.file_position = 0

                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    # Seek to last known position
                    f.seek(self.file_position)
                    
                    # Read new lines
                    new_lines = f.readlines()
                    
                    # Update position
                    self.file_position = f.tell()
                    
                    if new_lines:
                        # Process events, but batch UI refresh
                        for i, line in enumerate(new_lines):
                            line = line.strip()
                            if line:
                                try:
                                    event = json.loads(line)
                                    # Only update UI for the last 15 lines of a large burst to prevent freeze
                                    render_ui = (i >= len(new_lines) - 15)
                                    self.process_event(event, render_ui=render_ui)
                                except json.JSONDecodeError:
                                    pass
                        # Ensure final UI state reflects latest batch
                        self.update_action_list()
                        self.update_gauge()
                        self.update_stats()
        except Exception:
            pass
        
        # Schedule next poll
        self.root.after(POLL_INTERVAL_MS, self.poll_log_file)
    
    def process_event(self, event, render_ui=True):
        """Process a new event from the log"""
        # Update state
        self.last_packet_time = time.time()
        self.is_active = True
        
        if self.start_time is None:
            self.start_time = event.get('timestamp', time.time())
        
        self.current_action = event.get('action_id', 0)
        self.current_adversary_accuracy = event.get('adversary_accuracy', 0.0)
        llm = event.get('llm', '')
        self.current_llm = llm
        
        # Update statistics
        self.total_packets += 1
        if event.get('morphed_size') != event.get('original_size'):
            self.total_morphed += 1
        self.total_bytes_padded += event.get('bytes_padded', 0)
        if llm:
            self.active_llms.add(llm)
        
        # Add to recent packets
        self.recent_packets.append(event)
        
        # Update UI if requested
        if render_ui:
            self.update_packet_log(event)
    
    def update_action_list(self):
        """Update action list highlighting"""
        for action_id, (label, badge) in self.action_labels.items():
            if action_id == self.current_action:
                label.config(fg=COLOR_ACTIVE)
                badge.config(text="▶ ACTIVE")
            else:
                label.config(fg=COLOR_TEXT_DIM)
                badge.config(text="")
        
        # Update last action label
        action_name = ACTIONS.get(self.current_action, "Unknown")
        self.last_action_label.config(text=f"Last action: {action_name}")
    
    def update_packet_log(self, event):
        """Add new packet to scrolling log"""
        self.packet_log.config(state=tk.NORMAL)
        
        # Format timestamp
        ts = time.strftime("%H:%M:%S", time.localtime(event.get('timestamp', time.time())))
        llm = str(event.get('llm', '')).strip()
        
        # Use a mark at 1.0 with RIGHT gravity so pieces stay grouped as an intact 2-line unit at the top
        self.packet_log.mark_set("p_top", "1.0")
        self.packet_log.mark_gravity("p_top", tk.RIGHT)
        
        if llm:
            self.packet_log.insert("p_top", f"[{ts}] -> {llm}\n", "llm")
        else:
            self.packet_log.insert("p_top", f"[{ts}]\n", "timestamp")

        self.packet_log.insert("p_top", "  ORIGINAL: ", "timestamp")
        self.packet_log.insert("p_top", f"{event.get('original_size', 0)}B", "original")
        self.packet_log.insert("p_top", " -> MORPHED: ", "timestamp")
        self.packet_log.insert("p_top", f"{event.get('morphed_size', 1400)}B", "morphed")
        self.packet_log.insert("p_top", f" ({event.get('action_name', 'Morph')})\n", "action")

        # Keep only the newest MAX_LOG_LINES packets (2 lines per packet)
        try:
            self.packet_log.delete(f"{MAX_LOG_LINES * 2}.0", tk.END)
        except Exception:
            pass

        self.packet_log.config(state=tk.DISABLED)
    
    def update_gauge(self):
        """Adversary accuracy gauge removed per user request"""
        pass
    
    def update_stats(self):
        """Update bottom statistics bar"""
        # Packet stats
        self.stat_intercepted.config(text=str(self.total_packets))
        self.stat_morphed.config(text=str(self.total_morphed))
        
        # Format bytes padded
        if self.total_bytes_padded < 1024:
            bytes_str = f"{self.total_bytes_padded} B"
        elif self.total_bytes_padded < 1024 * 1024:
            bytes_str = f"{self.total_bytes_padded / 1024:.1f} KB"
        else:
            bytes_str = f"{self.total_bytes_padded / 1024 / 1024:.1f} MB"
        self.stat_padded.config(text=bytes_str)
    
    def update_status(self):
        """Update status indicator (pulsing dot)"""
        current_time = time.time()
        
        # Check if active (received packet in last 5 seconds)
        if self.last_packet_time > 0 and (current_time - self.last_packet_time) < ACTIVITY_TIMEOUT:
            if not self.is_active:
                self.is_active = True
            
            # Pulsing green effect (strictly clamped to [40, 255])
            pulse = max(40, min(255, int(147 + 107 * math.sin(current_time * 3))))
            color = f"#00{pulse:02x}00"
            
            self.status_dot.delete("all")
            self.status_dot.create_oval(2, 2, 18, 18, fill=color, outline="")
            self.status_label.config(text="PROTECTION ACTIVE", fg=COLOR_ACTIVE)
        else:
            if self.is_active or self.last_packet_time == 0:
                self.is_active = False
                self.status_dot.delete("all")
                self.status_dot.create_oval(2, 2, 18, 18, fill=COLOR_INACTIVE, outline="")
                self.status_label.config(text="WAITING FOR TRAFFIC...", fg=COLOR_INACTIVE)
        
        # Schedule next update
        self.root.after(100, self.update_status)
    
    def update_uptime(self):
        """Update uptime counter"""
        if self.start_time is not None:
            uptime_seconds = int(time.time() - self.start_time)
            hours = uptime_seconds // 3600
            minutes = (uptime_seconds % 3600) // 60
            seconds = uptime_seconds % 60
            uptime_str = f"Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}"
            self.uptime_label.config(text=uptime_str, fg=COLOR_TEXT)
        
        # Schedule next update
        self.root.after(1000, self.update_uptime)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = NeuroMorphDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
