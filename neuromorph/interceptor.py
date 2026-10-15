"""
Traffic Interceptor Module

Implements PyDivert-based packet capture targeting LLM API endpoints.
Provides async packet interception with configurable filtering.
"""

import asyncio
import logging
import socket
from typing import Callable, Optional, List
from collections import deque
import time

try:
    import pydivert
    PYDIVERT_AVAILABLE = True
except ImportError:
    PYDIVERT_AVAILABLE = False
    logging.warning("PyDivert not available. Install with: pip install pydivert")


class TrafficInterceptor:
    """
    User-space packet interceptor using WinDivert.
    
    Captures TCP traffic directed at specified LLM API endpoints,
    operating transparently without breaking the connection.
    """
    
    def __init__(self, config: dict):
        """
        Initialize the traffic interceptor.
        
        Args:
            config: Configuration dictionary containing network settings
        """
        if not PYDIVERT_AVAILABLE:
            raise ImportError("PyDivert is required. Run as Administrator and install pydivert.")
        
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Network configuration
        self.target_endpoints = config.get('network', {}).get('target_endpoints', [])
        self.target_ports = config.get('network', {}).get('target_ports', [443])
        
        # Multi-LLM support - load all configured LLM endpoints
        self.llm_providers = self._load_llm_providers(config)
        
        # Resolve endpoints to IP addresses
        self.target_ips = self._resolve_endpoints()
        
        # Build WinDivert filter string
        self.filter_string = self._build_filter()
        
        # Packet processing
        self.packet_callback: Optional[Callable] = None
        self.running = False
        self.packet_buffer = deque(maxlen=config.get('performance', {}).get('packet_buffer_size', 1000))
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'packets_forwarded': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': None,
        }
        
        self.logger.info(f"Traffic Interceptor initialized with filter: {self.filter_string}")
        self.logger.info(f"Protecting {len(self.llm_providers)} LLM providers: {', '.join(self.llm_providers.keys())}")
    
    def _load_llm_providers(self, config: dict) -> dict:
        """
        Load all configured LLM provider endpoints.
        
        Returns:
            Dictionary mapping provider name to endpoints
        """
        providers = {}
        
        # Default LLM providers with full web and API endpoints.
        # Covers web, desktop apps, mobile backends, CDN & API endpoints
        # for every major AI service.
        default_providers = {

            # ── OpenAI / ChatGPT (web + Windows/Mac desktop app) ─────────────
            'ChatGPT': [
                # Web
                'chatgpt.com', 'chat.openai.com', 'api.openai.com',
                'openai.com', 'auth.openai.com', 'platform.openai.com',
                'labs.openai.com',        # DALL-E web
                # ChatGPT desktop app (Windows / macOS Electron app)
                'ab.chatgpt.com',         # A/B testing endpoint used by desktop app
                'cdn.oaistatic.com',      # Static assets / UI files for desktop app
                'ai-cdn.openai.com',      # AI model CDN
                'production.dl.openai.com',   # Desktop app download / updates
                'desktop.production.dl.openai.com',  # Desktop app updater
                'updates.openai.com',     # App update service
                # Sora (OpenAI video AI)
                'sora.com', 'sora.openai.com',
                # Analytics / telemetry used by ChatGPT apps
                'o33249.ingest.sentry.io', # Sentry error tracking (OpenAI uses this)
            ],

            # ── Microsoft Copilot (Windows app, Edge sidebar, GitHub Copilot) ─
            'Copilot': [
                'copilot.microsoft.com', 'sydney.bing.com',
                'api.githubcopilot.com', 'copilot-proxy.githubusercontent.com',
                'edgeservices.bing.com', 'www.bing.com', 'bing.com',
                'r.bing.com', 'api.bing.com',
                'oai.azure.com', 'api.cognitive.microsoft.com',
                'eastus.api.cognitive.microsoft.com',
                'westus.api.cognitive.microsoft.com',
                'australiaeast.api.cognitive.microsoft.com',
                'login.microsoftonline.com',
                'github.com', 'api.github.com',
                'copilot.github.com',
            ],

            # ── Google Gemini (web, desktop PWA, Android app, Vertex AI) ──────
            'Gemini': [
                'gemini.google.com', 'generativelanguage.googleapis.com',
                'ai.google.dev', 'aistudio.google.com', 'bard.google.com',
                'content-sniffing.googleapis.com',
                'accounts.google.com', 'lh3.googleusercontent.com',
                'us-central1-aiplatform.googleapis.com',
                'aiplatform.googleapis.com', 'vertexai.googleapis.com',
                'cloudfunctions.net',
            ],

            # ── Anthropic Claude (web + Windows/Mac desktop app) ──────────────
            'Claude': [
                # Web
                'claude.ai', 'api.anthropic.com', 'anthropic.com',
                'www.claude.ai',
                # Claude desktop app (Windows / macOS Electron app)
                'desktop.claude.ai',          # Desktop app specific endpoint
                'cdn.anthropic.com',          # Static assets for desktop app
                'statsig.anthropic.com',      # Feature flags / analytics (desktop app)
                'sentry.io',                  # Error tracking used by Claude app
                'o4504578800238592.ingest.sentry.io',  # Anthropic's Sentry project
                # Claude app update service
                'releases.anthropic.com',
            ],

            # ── Perplexity AI ─────────────────────────────────────────────────
            'Perplexity': [
                'perplexity.ai', 'api.perplexity.ai', 'www.perplexity.ai',
                'labs.perplexity.ai',
            ],

            # ── Cohere ────────────────────────────────────────────────────────
            'Cohere': [
                'api.cohere.ai', 'cohere.ai', 'cohere.com',
                'dashboard.cohere.com',
            ],

            # ── Mistral AI ────────────────────────────────────────────────────
            'Mistral': [
                'api.mistral.ai', 'mistral.ai', 'console.mistral.ai',
                'chat.mistral.ai', 'le-chat.mistral.ai',
            ],

            # ── HuggingFace ───────────────────────────────────────────────────
            'HuggingFace': [
                'huggingface.co', 'api-inference.huggingface.co',
                'huggingfaceh4.github.io',
            ],

            # ── xAI Grok ──────────────────────────────────────────────────────
            'Grok': [
                'grok.com', 'x.ai', 'api.x.ai',
                'grok.x.ai', 'www.grok.com',
                # X / Twitter (Grok is embedded inside X app)
                'twitter.com', 'api.twitter.com', 'x.com',
                'abs.twimg.com', 'api.x.com',
            ],

            # ── Meta AI (meta.ai, WhatsApp AI, Instagram AI) ──────────────────
            'Meta AI': [
                'meta.ai', 'ai.meta.com', 'www.meta.ai',
                'llama.meta.com', 'llama-api.meta.com',
                # Meta AI inside WhatsApp / Instagram / Messenger / Facebook
                'api.whatsapp.com', 'graph.facebook.com',
                'www.facebook.com', 'edge-chat.facebook.com',
                'www.instagram.com', 'i.instagram.com',
                'messenger.com', 'api.messenger.com',
            ],

            # ── DeepSeek ──────────────────────────────────────────────────────
            'DeepSeek': [
                'deepseek.com', 'api.deepseek.com',
                'chat.deepseek.com', 'www.deepseek.com',
            ],

            # ── Groq (fast inference) ─────────────────────────────────────────
            'Groq': [
                'groq.com', 'api.groq.com',
                'console.groq.com', 'www.groq.com',
            ],

            # ── Character.AI ──────────────────────────────────────────────────
            'Character.AI': [
                'character.ai', 'beta.character.ai',
                'www.character.ai', 'api.character.ai',
                'plus.character.ai',
            ],

            # ── Stability AI (Stable Diffusion / SDXL) ────────────────────────
            'Stability AI': [
                'stability.ai', 'api.stability.ai',
                'dreamstudio.ai', 'www.stability.ai',
                'clipdrop.co',
            ],

            # ── ElevenLabs (AI voice) ─────────────────────────────────────────
            'ElevenLabs': [
                'elevenlabs.io', 'api.elevenlabs.io',
                'www.elevenlabs.io',
            ],

            # ── Runway ML (AI video) ──────────────────────────────────────────
            'Runway': [
                'runwayml.com', 'api.runwayml.com',
                'app.runwayml.com', 'www.runwayml.com',
            ],

            # ── Pika Labs (AI video) ──────────────────────────────────────────
            'Pika': [
                'pika.art', 'www.pika.art',
            ],

            # ── Pi AI / Inflection ────────────────────────────────────────────
            'Pi': [
                'pi.ai', 'www.pi.ai',
                'inflection.ai', 'www.inflection.ai',
            ],

            # ── You.com ───────────────────────────────────────────────────────
            'You.com': [
                'you.com', 'api.you.com', 'www.you.com',
            ],

            # ── Together AI ───────────────────────────────────────────────────
            'Together AI': [
                'together.ai', 'api.together.xyz',
                'api.together.ai', 'www.together.ai',
            ],

            # ── Replicate ─────────────────────────────────────────────────────
            'Replicate': [
                'replicate.com', 'api.replicate.com',
                'www.replicate.com',
            ],

            # ── Amazon Bedrock / Alexa AI ──────────────────────────────────────
            'Amazon AI': [
                'bedrock.us-east-1.amazonaws.com',
                'bedrock-runtime.us-east-1.amazonaws.com',
                'bedrock.us-west-2.amazonaws.com',
                'bedrock-runtime.us-west-2.amazonaws.com',
                'alexa.amazon.com', 'api.amazonalexa.com',
            ],

            # ── Adobe Firefly ─────────────────────────────────────────────────
            'Adobe Firefly': [
                'firefly.adobe.com', 'adobefirefly.com',
                'api.adobe.io',
            ],

            # ── Midjourney ────────────────────────────────────────────────────
            'Midjourney': [
                'midjourney.com', 'www.midjourney.com',
                'cdn.midjourney.com',
                # MJ Discord bot backend
                'discord.com', 'discord.gg', 'discordapp.com',
                'cdn.discordapp.com',
            ],

            # ── Suno AI (AI music) ────────────────────────────────────────────
            'Suno': [
                'suno.com', 'suno.ai', 'www.suno.ai',
                'app.suno.ai', 'cdn2.suno.ai',
            ],

            # ── Udio (AI music) ───────────────────────────────────────────────
            'Udio': [
                'udio.com', 'www.udio.com', 'api.udio.com',
            ],

            # ── Qwen / Alibaba AI ─────────────────────────────────────────────
            'Qwen': [
                'qwen.aliyun.com', 'dashscope.aliyuncs.com',
                'chat.qwen.ai', 'tongyi.aliyun.com',
            ],

            # ── Kimi / Moonshot AI ────────────────────────────────────────────
            'Kimi': [
                'kimi.ai', 'www.kimi.ai', 'api.moonshot.cn',
                'moonshot.cn',
            ],

            # ── Jasper AI ─────────────────────────────────────────────────────
            'Jasper': [
                'jasper.ai', 'app.jasper.ai', 'api.jasper.ai',
            ],

            # ── Copy.ai ───────────────────────────────────────────────────────
            'Copy.ai': [
                'copy.ai', 'www.copy.ai', 'app.copy.ai',
            ],

            # ── Notion AI ─────────────────────────────────────────────────────
            'Notion AI': [
                'notion.so', 'www.notion.so', 'api.notion.com',
            ],

            # ── Cursor AI (IDE) ───────────────────────────────────────────────
            'Cursor': [
                'cursor.so', 'www.cursor.com', 'cursor.com',
                'api.cursor.sh', 'api2.cursor.sh',
            ],

            # ── Codeium / Windsurf ────────────────────────────────────────────
            'Codeium': [
                'codeium.com', 'api.codeium.com', 'www.codeium.com',
                'windsurf.com', 'www.windsurf.com',
            ],

            # ── Tabnine ───────────────────────────────────────────────────────
            'Tabnine': [
                'tabnine.com', 'api.tabnine.com', 'www.tabnine.com',
            ],

            # ── Writesonic ────────────────────────────────────────────────────
            'Writesonic': [
                'writesonic.com', 'app.writesonic.com',
            ],

            # ── Grammarly (AI writing) ────────────────────────────────────────
            'Grammarly': [
                'grammarly.com', 'api.grammarly.com',
                'app.grammarly.com',
            ],

        }
        
        # Load from config or use defaults
        llm_config = config.get('llm_endpoints', {})
        
        # Merge with defaults
        for provider, endpoints in default_providers.items():
            cfg_key = provider.lower()
            if cfg_key in llm_config:
                cfg_list = llm_config[cfg_key] if isinstance(llm_config[cfg_key], list) else [llm_config[cfg_key]]
                providers[provider] = list(set(endpoints + cfg_list))
            else:
                providers[provider] = endpoints
        
        # Add any custom providers from config
        for provider, endpoints in llm_config.items():
            p_name = provider.capitalize()
            if p_name not in providers:
                providers[p_name] = endpoints if isinstance(endpoints, list) else [endpoints]
        
        # Flatten to single list of endpoints for target_endpoints
        all_endpoints = []
        for endpoints in providers.values():
            all_endpoints.extend(endpoints)
        
        # Update target_endpoints with all LLM endpoints
        self.target_endpoints = list(set(all_endpoints))
        
        return providers
    
    def _resolve_endpoints(self) -> List[str]:
        """
        Resolve domain names to IP addresses (both IPv4 and IPv6).
        Builds provider_ip_map for exact LLM identification.
        """
        self.provider_ip_map = {provider: set() for provider in self.llm_providers.keys()}
        all_ips = set()
        
        for provider, endpoints in self.llm_providers.items():
            for endpoint in endpoints:
                try:
                    addr_info = socket.getaddrinfo(endpoint, 443)
                    for item in addr_info:
                        ip = item[4][0]
                        self.provider_ip_map[provider].add(ip)
                        all_ips.add(ip)
                    self.logger.info(f"Resolved {endpoint} ({provider}) -> {len(self.provider_ip_map[provider])} IPs")
                except Exception as e:
                    self.logger.warning(f"Failed to resolve {endpoint}: {e}")
                    
        return list(all_ips)
    
    def identify_provider(self, ip: str) -> str:
        """
        Identify which LLM provider an IP belongs to.
        First tries exact IP match from resolved endpoints.
        Falls back to subnet/prefix matching for desktop apps that
        use IPs not resolved at startup (CDN, Azure, Google cloud).
        Returns provider name (e.g. 'ChatGPT', 'Copilot') or '' if normal traffic.
        """
        if not ip or not hasattr(self, 'provider_ip_map'):
            return ""

        # --- Exact match (fast path) ---
        for provider, ip_set in self.provider_ip_map.items():
            if ip in ip_set:
                return provider

        # --- Subnet / prefix fallback ---
        # Used when exact DNS resolution didn't capture the IP at startup
        # (CDN rotation, regional IPs, dynamic cloud IPs, etc.)

        # Microsoft / Bing / Azure → Copilot
        MICROSOFT_PREFIXES = (
            '13.107.',    # Microsoft global CDN
            '40.126.',    # Azure AD / Microsoft services
            '52.184.',    # Azure East US
            '52.180.',    # Azure
            '20.190.',    # Azure AD
            '20.60.',     # Azure Front Door / Copilot
            '20.42.',     # Azure
            '20.36.',     # Azure
            '20.231.',    # Azure
            '40.112.',    # Azure
            '13.69.',     # Azure West Europe
            '13.77.',     # Azure West US
            '204.79.',    # Bing CDN (Akamai)
            '40.125.',    # Azure
        )

        # Google → Gemini
        GOOGLE_PREFIXES = (
            '142.250.',
            '142.251.',
            '172.217.',
            '172.253.',
            '74.125.',
            '64.233.',
            '66.102.',
            '216.58.',
            '66.249.',
            '108.177.',
            '209.85.',
            '34.96.',     # Google Cloud / Vertex AI
            '34.102.',
            '34.120.',
        )

        # OpenAI / ChatGPT (Cloudflare)
        OPENAI_PREFIXES = (
            '172.66.',    # Cloudflare (OpenAI uses Cloudflare)
            '104.18.',    # Cloudflare
            '104.16.',    # Cloudflare
            '104.17.',    # Cloudflare
        )

        # Anthropic / Claude (Cloudflare + AWS CloudFront)
        ANTHROPIC_PREFIXES = (
            '160.79.',    # Anthropic direct
            '13.33.',     # AWS CloudFront
            '13.35.',     # AWS CloudFront
        )

        # Meta AI (Facebook, WhatsApp, Instagram, Meta AI app)
        META_PREFIXES = (
            '157.240.',   # Facebook / Meta global
            '31.13.',     # Facebook / Meta
            '163.70.',    # Meta
            '163.71.',
            '163.77.',
            '66.220.',    # Facebook CDN
            '69.171.',    # Facebook
            '69.63.',     # Facebook
        )

        # xAI / Grok (Twitter / X IPs)
        XAI_PREFIXES = (
            '104.244.',   # Twitter / X
            '192.133.',   # Twitter / X
            '199.16.',    # Twitter CDN
            '185.45.',    # xAI / Grok direct
        )

        # Amazon AI / Bedrock (AWS)
        AWS_PREFIXES = (
            '52.46.',     # AWS us-east-1
            '52.94.',     # AWS
            '54.240.',    # AWS
            '18.68.',     # AWS Bedrock
            '3.5.',       # AWS
        )

        for prefix in MICROSOFT_PREFIXES:
            if ip.startswith(prefix):
                return 'Copilot'
        for prefix in GOOGLE_PREFIXES:
            if ip.startswith(prefix):
                return 'Gemini'
        for prefix in OPENAI_PREFIXES:
            if ip.startswith(prefix):
                return 'ChatGPT'
        for prefix in ANTHROPIC_PREFIXES:
            if ip.startswith(prefix):
                return 'Claude'
        for prefix in META_PREFIXES:
            if ip.startswith(prefix):
                return 'Meta AI'
        for prefix in XAI_PREFIXES:
            if ip.startswith(prefix):
                return 'Grok'
        for prefix in AWS_PREFIXES:
            if ip.startswith(prefix):
                return 'Amazon AI'

        return ""


    
    def _build_filter(self) -> str:
        """
        Build WinDivert filter string.
        Uses a simple port-443 filter (both TCP and UDP/QUIC).
        LLM-specific filtering is done in the packet callback via IP lookup.
        This is more reliable than IP-based WinDivert filters because
        browser IPs can differ from what was resolved at startup.

        Returns:
            WinDivert filter string
        """
        return "tcp.DstPort == 443 or udp.DstPort == 443"
    
    def set_packet_callback(self, callback: Callable):
        """
        Set the callback function for packet processing.
        
        Args:
            callback: Async function to process each packet
        """
        self.packet_callback = callback
    
    async def start(self):
        """
        Start packet interception loop.
        
        This method runs indefinitely until stop() is called.
        Must be run with administrator privileges.
        """
        if not PYDIVERT_AVAILABLE:
            raise RuntimeError("PyDivert not available")
        
        self.running = True
        self.stats['start_time'] = time.time()
        
        self.logger.info("Starting traffic interception...")
        
        try:
            # Open WinDivert handle
            with pydivert.WinDivert(self.filter_string) as w:
                self.logger.info("WinDivert handle opened successfully")
                
                while self.running:
                    try:
                        # Receive packet with generous 1MB buffer to prevent WinError 122
                        try:
                            packet = w.recv(1048576)
                        except OSError as oe:
                            if getattr(oe, 'winerror', None) == 122:
                                continue
                            raise

                        if packet is None:
                            continue
                        
                        # Update statistics
                        self.stats['packets_captured'] += 1
                        self.stats['bytes_captured'] += len(packet.payload) if packet.payload else 0

                        # Debug: log every 10th packet so we know traffic is flowing
                        if self.stats['packets_captured'] % 10 == 1:
                            self.logger.info(f"[DEBUG] Packet #{self.stats['packets_captured']} captured - size={len(packet.payload) if packet.payload else 0}B")
                        
                        # Add timestamp and destination IP for LLM identification
                        # Try packet.dst_addr first; fall back to ipv4 header field
                        dst_addr = None
                        if hasattr(packet, 'dst_addr') and packet.dst_addr:
                            dst_addr = packet.dst_addr
                        elif hasattr(packet, 'ipv4') and packet.ipv4 is not None and hasattr(packet.ipv4, 'dst_addr'):
                            dst_addr = packet.ipv4.dst_addr

                        packet_data = {
                            'packet': packet,
                            'timestamp': time.time(),
                            'size': len(packet.payload) if packet.payload else 0,
                            'dst_addr': dst_addr,
                        }

                        # Quick LLM check - log first occurrence of each LLM provider
                        if dst_addr:
                            provider = self.identify_provider(dst_addr)
                            if provider and not getattr(self, '_logged_providers', None):
                                self._logged_providers = set()
                            if provider and provider not in getattr(self, '_logged_providers', set()):
                                self.logger.info(f"[LLM DETECTED] {provider} traffic -> {dst_addr}")
                                if not hasattr(self, '_logged_providers'):
                                    self._logged_providers = set()
                                self._logged_providers.add(provider)
                        
                        # Immediately forward raw packet so browser traffic is never blocked or corrupted
                        try:
                            w.send(packet)
                            self.stats['packets_forwarded'] += 1
                        except Exception:
                            pass

                        # Process packet through DRL morphing engine for live telemetry and dashboard
                        if self.packet_callback:
                            try:
                                await self.packet_callback(packet_data)
                            except Exception:
                                pass

                        # Allow other tasks to run
                        await asyncio.sleep(0)

                    except Exception as e:
                        self.logger.error(f"Error processing packet: {e}")
                        continue
                        
        except PermissionError:
            self.logger.error("Permission denied. Run as Administrator to use WinDivert.")
            raise
        except Exception as e:
            self.logger.error(f"Error in interception loop: {e}")
            raise
        finally:
            self.logger.info("Traffic interception stopped")
    
    def stop(self):
        """Stop packet interception."""
        self.logger.info("Stopping traffic interceptor...")
        self.running = False
    
    def get_statistics(self) -> dict:
        """
        Get interception statistics.
        
        Returns:
            Dictionary containing statistics
        """
        if self.stats['start_time']:
            runtime = time.time() - self.stats['start_time']
            self.stats['runtime_seconds'] = runtime
            self.stats['packets_per_second'] = self.stats['packets_captured'] / runtime if runtime > 0 else 0
        
        return self.stats.copy()
    
    def reset_statistics(self):
        """Reset all statistics counters."""
        self.stats = {
            'packets_captured': 0,
            'packets_forwarded': 0,
            'packets_dropped': 0,
            'bytes_captured': 0,
            'start_time': time.time() if self.running else None,
        }


class ObservationalInterceptor(TrafficInterceptor):
    """
    Phase 1 interceptor that only observes traffic without modification.
    Used for baseline data collection.
    """
    
    def __init__(self, config: dict, log_file: str = "data/baseline_traffic.csv"):
        """
        Initialize observational interceptor.
        
        Args:
            config: Configuration dictionary
            log_file: Path to save captured traffic data
        """
        super().__init__(config)
        self.log_file = log_file
        self.packet_log = []
        
        # Create log file header
        import os
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    async def log_packet(self, packet_data: dict) -> dict:
        """
        Log packet metadata without modification.
        
        Args:
            packet_data: Packet information dictionary
            
        Returns:
            Action to forward packet unchanged
        """
        packet = packet_data['packet']
        
        # Extract features
        metadata = {
            'timestamp': packet_data['timestamp'],
            'size': packet_data['size'],
            'src_addr': packet.src_addr if hasattr(packet, 'src_addr') else None,
            'dst_addr': packet.dst_addr if hasattr(packet, 'dst_addr') else None,
            'src_port': packet.src_port if hasattr(packet, 'src_port') else None,
            'dst_port': packet.dst_port if hasattr(packet, 'dst_port') else None,
            'seq': None,  # Not available in this PyDivert version
            'ack': None,  # Not available in this PyDivert version
            'flags': self._extract_tcp_flags(packet),
        }
        
        self.packet_log.append(metadata)
        
        # Forward unchanged
        return {'action': 'forward'}
    
    def _extract_tcp_flags(self, packet) -> str:
        """Extract TCP flags as string."""
        # PyDivert 3.x doesn't expose individual TCP flags easily
        # Return empty string for now
        return ""
    
    def save_log(self):
        """Save captured packet log to CSV file."""
        import pandas as pd
        
        if self.packet_log:
            df = pd.DataFrame(self.packet_log)
            df.to_csv(self.log_file, index=False)
            self.logger.info(f"Saved {len(self.packet_log)} packets to {self.log_file}")
        else:
            self.logger.warning("No packets to save")
