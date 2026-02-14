import ipaddress
import logging


logger = logging.getLogger("peerix.net_validation")


def is_localhost(host: str) -> bool:
    """Check if host is a localhost address (IPv4 or IPv6)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost", "localhost.localdomain")
    return addr.is_loopback


def is_safe_peer_address(addr: str) -> bool:
    """Validate that a peer address is safe for WAN use.

    Blocks loopback, link-local, metadata IPs, multicast, and unspecified.
    Does NOT block private RFC1918 (needed for test-vm with 10.0.2.2).
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        logger.warning(f"Invalid IP address: {addr}")
        return False

    if ip.is_loopback:
        logger.debug(f"Rejected loopback address: {addr}")
        return False

    if ip.is_link_local:
        logger.debug(f"Rejected link-local address: {addr}")
        return False

    if ip.is_multicast:
        logger.debug(f"Rejected multicast address: {addr}")
        return False

    if ip.is_unspecified:
        logger.debug(f"Rejected unspecified address: {addr}")
        return False

    # Block cloud metadata endpoint
    if addr == "169.254.169.254":
        logger.debug(f"Rejected metadata address: {addr}")
        return False

    return True


def is_safe_lan_address(addr: str) -> bool:
    """Validate that a LAN peer address is safe.

    Same as is_safe_peer_address but also requires the address to be private.
    """
    if not is_safe_peer_address(addr):
        return False

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False

    if not ip.is_private:
        logger.debug(f"Rejected non-private address for LAN: {addr}")
        return False

    return True
