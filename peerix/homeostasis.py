"""
IPFS Homeostasis Daemon

Monitors network health and dynamically adjusts IPFS peer connections
to prevent network flooding while maintaining functionality.
"""

import asyncio
import logging
import subprocess
import time
import typing as t
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


@dataclass
class HomeostasisConfig:
    """Configuration for homeostasis daemon."""
    # Target peer count (start very low)
    min_peers: int = 2
    max_peers: int = 5

    # Latency thresholds (ms)
    latency_ok: float = 30.0      # Below this = healthy
    latency_warn: float = 80.0    # Above this = start disconnecting
    latency_critical: float = 150.0  # Above this = aggressive disconnect

    # Ping target (default: gateway)
    ping_target: str = ""  # Empty = auto-detect gateway

    # Check intervals
    check_interval: float = 5.0   # Seconds between checks
    recovery_time: float = 60.0   # Seconds of good health before increasing peers

    # IPFS API
    ipfs_api: str = "http://127.0.0.1:5001/api/v0"

    # Disconnect batch size (percentage of peers to drop)
    disconnect_percent: float = 0.3  # Drop 30% of peers when unhealthy

    # Peerix integration
    peerix_url: str = "http://127.0.0.1:12304"


@dataclass
class NetworkState:
    """Current network state."""
    latency_ms: float = 0.0
    packet_loss: float = 0.0
    peer_count: int = 0
    last_healthy: float = 0.0
    consecutive_unhealthy: int = 0
    dht_paused: bool = False


class HomeostasisDaemon:
    """Maintains network homeostasis by managing IPFS peers."""

    def __init__(self, config: HomeostasisConfig = None):
        self.config = config or HomeostasisConfig()
        self.state = NetworkState()
        self._running = False
        self._http: t.Optional[httpx.AsyncClient] = None
        self._gateway: t.Optional[str] = None

    async def start(self):
        """Start the homeostasis daemon."""
        self._running = True
        self._http = httpx.AsyncClient(timeout=10.0)

        # Detect gateway if not configured
        if not self.config.ping_target:
            self._gateway = self._detect_gateway()
            logger.info(f"Auto-detected gateway: {self._gateway}")
        else:
            self._gateway = self.config.ping_target

        if not self._gateway:
            logger.error("Could not detect gateway, using 8.8.8.8")
            self._gateway = "8.8.8.8"

        logger.info(f"Homeostasis daemon starting (target peers: {self.config.min_peers}-{self.config.max_peers})")

        # Initial aggressive peer reduction
        await self._enforce_max_peers()

        while self._running:
            try:
                await self._check_cycle()
            except Exception as e:
                logger.error(f"Homeostasis check failed: {e}")

            await asyncio.sleep(self.config.check_interval)

    async def stop(self):
        """Stop the daemon."""
        self._running = False
        if self._http:
            await self._http.aclose()

    def _detect_gateway(self) -> t.Optional[str]:
        """Detect default gateway IP."""
        try:
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5
            )
            # Parse: "default via 192.168.1.1 dev eth0"
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    idx = parts.index('via') + 1
                    return parts[idx]
        except Exception as e:
            logger.warning(f"Failed to detect gateway: {e}")
        return None

    async def _measure_latency(self) -> t.Tuple[float, float]:
        """Measure latency and packet loss to gateway. Returns (latency_ms, loss_percent)."""
        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", self._gateway],
                capture_output=True, text=True, timeout=10
            )

            # Parse ping output
            output = result.stdout

            # Get packet loss
            loss = 0.0
            if "packet loss" in output:
                for part in output.split():
                    if part.endswith('%'):
                        try:
                            loss = float(part.rstrip('%'))
                            break
                        except ValueError:
                            pass

            # Get average latency
            latency = 999.0
            if "avg" in output or "rtt" in output:
                # Format: rtt min/avg/max/mdev = 1.234/5.678/9.012/1.234 ms
                for line in output.split('\n'):
                    if 'avg' in line and '/' in line:
                        try:
                            # Extract the avg value (second number after =)
                            stats = line.split('=')[1].strip().split('/')[1]
                            latency = float(stats)
                            break
                        except (IndexError, ValueError):
                            pass

            return latency, loss

        except subprocess.TimeoutExpired:
            return 999.0, 100.0
        except Exception as e:
            logger.warning(f"Ping failed: {e}")
            return 999.0, 100.0

    async def _get_peer_count(self) -> int:
        """Get current IPFS peer count."""
        try:
            resp = await self._http.post(f"{self.config.ipfs_api}/swarm/peers")
            if resp.status_code == 200:
                data = resp.json()
                peers = data.get("Peers") or []
                return len(peers)
        except Exception as e:
            logger.warning(f"Failed to get peer count: {e}")
        return 0

    async def _get_peers(self) -> t.List[str]:
        """Get list of peer multiaddrs."""
        try:
            resp = await self._http.post(f"{self.config.ipfs_api}/swarm/peers")
            if resp.status_code == 200:
                data = resp.json()
                peers = data.get("Peers") or []
                return [p.get("Addr", "") + "/p2p/" + p.get("Peer", "") for p in peers]
        except Exception as e:
            logger.warning(f"Failed to get peers: {e}")
        return []

    async def _disconnect_peer(self, peer_addr: str) -> bool:
        """Disconnect a specific peer."""
        try:
            resp = await self._http.post(
                f"{self.config.ipfs_api}/swarm/disconnect",
                params={"arg": peer_addr}
            )
            return resp.status_code == 200
        except Exception as e:
            logger.warning(f"Failed to disconnect peer: {e}")
            return False

    async def _disconnect_random_peers(self, count: int):
        """Disconnect random peers."""
        import random
        peers = await self._get_peers()
        if not peers:
            return

        to_disconnect = random.sample(peers, min(count, len(peers)))
        disconnected = 0

        for peer in to_disconnect:
            if await self._disconnect_peer(peer):
                disconnected += 1

        logger.info(f"Disconnected {disconnected}/{count} peers")

    async def _enforce_max_peers(self):
        """Ensure peer count doesn't exceed max."""
        peer_count = await self._get_peer_count()
        self.state.peer_count = peer_count

        if peer_count > self.config.max_peers:
            excess = peer_count - self.config.max_peers
            logger.info(f"Peer count {peer_count} exceeds max {self.config.max_peers}, disconnecting {excess}")
            await self._disconnect_random_peers(excess)

    async def _pause_dht_announce(self):
        """Pause peerix DHT announcements."""
        if self.state.dht_paused:
            return
        try:
            resp = await self._http.post(f"{self.config.peerix_url}/reannounce/pause")
            if resp.status_code == 200:
                self.state.dht_paused = True
                logger.info("Paused DHT announce")
        except Exception as e:
            logger.warning(f"Failed to pause DHT: {e}")

    async def _resume_dht_announce(self):
        """Resume peerix DHT announcements."""
        if not self.state.dht_paused:
            return
        try:
            resp = await self._http.post(f"{self.config.peerix_url}/reannounce/resume")
            if resp.status_code == 200:
                self.state.dht_paused = False
                logger.info("Resumed DHT announce")
        except Exception as e:
            logger.warning(f"Failed to resume DHT: {e}")

    async def _check_cycle(self):
        """Run one check cycle."""
        now = time.time()

        # Measure network health
        latency, loss = await self._measure_latency()
        self.state.latency_ms = latency
        self.state.packet_loss = loss

        # Get peer count
        peer_count = await self._get_peer_count()
        self.state.peer_count = peer_count

        # Determine health status
        is_healthy = (
            latency < self.config.latency_ok and
            loss < 5.0 and
            peer_count <= self.config.max_peers
        )

        is_critical = (
            latency > self.config.latency_critical or
            loss > 30.0
        )

        is_warning = (
            latency > self.config.latency_warn or
            loss > 10.0 or
            peer_count > self.config.max_peers
        )

        # Log status periodically
        status = "OK" if is_healthy else ("CRITICAL" if is_critical else ("WARN" if is_warning else "OK"))
        logger.debug(f"Network: {latency:.1f}ms, {loss:.0f}% loss, {peer_count} peers [{status}]")

        if is_healthy:
            self.state.last_healthy = now
            self.state.consecutive_unhealthy = 0

            # Resume DHT if paused and healthy for a while
            if self.state.dht_paused and (now - self.state.last_healthy) > 30:
                await self._resume_dht_announce()

        elif is_critical:
            self.state.consecutive_unhealthy += 1
            logger.warning(f"CRITICAL: {latency:.1f}ms latency, {loss:.0f}% loss, {peer_count} peers")

            # Aggressive response
            await self._pause_dht_announce()

            # Disconnect most peers, keep only min
            if peer_count > self.config.min_peers:
                to_drop = peer_count - self.config.min_peers
                await self._disconnect_random_peers(to_drop)

        elif is_warning:
            self.state.consecutive_unhealthy += 1
            logger.info(f"Warning: {latency:.1f}ms latency, {loss:.0f}% loss, {peer_count} peers")

            # Moderate response
            if self.state.consecutive_unhealthy >= 2:
                await self._pause_dht_announce()

            # Disconnect some peers
            if peer_count > self.config.max_peers:
                drop_count = int(peer_count * self.config.disconnect_percent)
                drop_count = max(1, drop_count)
                await self._disconnect_random_peers(drop_count)

        # Always enforce max peers
        if peer_count > self.config.max_peers:
            await self._enforce_max_peers()

    def get_status(self) -> t.Dict[str, t.Any]:
        """Get current homeostasis status."""
        return {
            "latency_ms": self.state.latency_ms,
            "packet_loss": self.state.packet_loss,
            "peer_count": self.state.peer_count,
            "dht_paused": self.state.dht_paused,
            "consecutive_unhealthy": self.state.consecutive_unhealthy,
            "config": {
                "min_peers": self.config.min_peers,
                "max_peers": self.config.max_peers,
                "latency_ok": self.config.latency_ok,
                "latency_warn": self.config.latency_warn,
                "latency_critical": self.config.latency_critical,
            }
        }


async def run_homeostasis(
    min_peers: int = 2,
    max_peers: int = 5,
    latency_warn: float = 80.0,
    latency_critical: float = 150.0,
    check_interval: float = 5.0,
    ping_target: str = "",
) -> HomeostasisDaemon:
    """Create and start homeostasis daemon with given config."""
    config = HomeostasisConfig(
        min_peers=min_peers,
        max_peers=max_peers,
        latency_warn=latency_warn,
        latency_critical=latency_critical,
        check_interval=check_interval,
        ping_target=ping_target,
    )
    daemon = HomeostasisDaemon(config)
    return daemon
