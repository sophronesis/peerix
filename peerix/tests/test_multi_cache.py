"""
Tests for multi-cache support.

Run with: pytest peerix/tests/test_multi_cache.py -v
"""
import pytest
import tempfile
import os
from pathlib import Path


class TestCacheRegistry:
    """Test CacheRegistry functionality."""

    def test_registry_initialization(self):
        """Test basic registry initialization."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        assert len(registry._caches) == 0

    def test_add_cache(self):
        """Test adding a cache to registry."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        )
        assert len(registry._caches) == 1
        assert registry.is_trusted("https://cache.nixos.org")

    def test_add_cache_normalizes_url(self):
        """Test that URLs are normalized (trailing slash removed)."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org/",
            "cache.nixos.org-1:key"
        )
        assert registry.is_trusted("https://cache.nixos.org")
        assert registry.is_trusted("https://cache.nixos.org/")

    def test_get_cache_for_key(self):
        """Test looking up cache URL by key name."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        )
        assert registry.get_cache_for_key("cache.nixos.org-1") == "https://cache.nixos.org"
        assert registry.get_cache_for_key("unknown-key") is None

    def test_get_key_for_cache(self):
        """Test looking up public key by cache URL."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        )
        key = registry.get_key_for_cache("https://cache.nixos.org")
        assert key == "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="

    def test_is_key_trusted(self):
        """Test checking if a key is from a trusted cache."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:key"
        )
        assert registry.is_key_trusted("cache.nixos.org-1")
        assert not registry.is_key_trusted("untrusted-cache-1")

    def test_find_origin_by_signature(self):
        """Test finding origin from signature."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        )

        # Valid signature format
        result = registry.find_origin_by_signature("cache.nixos.org-1:somesignature")
        assert result is not None
        cache_url, public_key = result
        assert cache_url == "https://cache.nixos.org"
        assert public_key.startswith("cache.nixos.org-1:")

        # Unknown key
        result = registry.find_origin_by_signature("unknown-cache-1:somesignature")
        assert result is None

    def test_get_trusted_caches_payload(self):
        """Test generating payload for tracker announcement."""
        from peerix.cache_registry import CacheRegistry
        registry = CacheRegistry()
        registry.add_cache(
            "https://cache.nixos.org",
            "cache.nixos.org-1:key1"
        )
        registry.add_cache(
            "https://my-cache.example.com",
            "my-cache-1:key2"
        )

        payload = registry.get_trusted_caches_payload()
        assert len(payload) == 2
        assert all("url" in item and "public_key" in item for item in payload)

    def test_registry_from_config(self):
        """Test initializing registry from config."""
        from peerix.cache_registry import CacheRegistry
        from peerix.config import CachesConfig, TrustedCache

        config = CachesConfig(
            default="https://cache.nixos.org",
            default_key="cache.nixos.org-1:key1",
            trusted_caches=[
                TrustedCache(url="https://other-cache.com", public_key="other-cache-1:key2")
            ],
            auto_detect=False,
        )

        registry = CacheRegistry(config)
        assert registry.is_trusted("https://cache.nixos.org")
        assert registry.is_trusted("https://other-cache.com")


class TestOriginDetector:
    """Test OriginDetector functionality."""

    def test_detector_initialization(self):
        """Test basic detector initialization."""
        from peerix.origin_detector import OriginDetector
        from peerix.cache_registry import CacheRegistry

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, "origin_cache.json")
            registry = CacheRegistry()
            detector = OriginDetector(registry, cache_file=cache_file)
            assert detector is not None

    def test_extract_package_name(self):
        """Test extracting package name from store path."""
        from peerix.origin_detector import OriginDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, "origin_cache.json")
            detector = OriginDetector(cache_file=cache_file)

            # Standard format
            name = detector._extract_package_name("/nix/store/abc12345678901234567890123456789-hello-2.12.2")
            assert name == "hello-2.12.2"

            # Just basename
            name = detector._extract_package_name("abc12345678901234567890123456789-curl-8.0.0")
            assert name == "curl-8.0.0"

    def test_cache_persistence(self):
        """Test that origin cache is persisted and loaded."""
        from peerix.origin_detector import OriginDetector, OriginInfo
        from peerix.cache_registry import CacheRegistry

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, "origin_cache.json")
            registry = CacheRegistry()

            # Create detector and add an origin
            detector = OriginDetector(registry, cache_file=cache_file)
            origin = OriginInfo(
                cache_url="https://cache.nixos.org",
                public_key="cache.nixos.org-1:key",
                package_name="hello-2.12.2"
            )
            detector.set_origin("abc12345678901234567890123456789", origin)
            detector.save_cache()

            # Create new detector and verify it loads the cache
            detector2 = OriginDetector(registry, cache_file=cache_file)
            loaded = detector2.get_cached_origin("abc12345678901234567890123456789")
            assert loaded is not None
            assert loaded.cache_url == "https://cache.nixos.org"
            assert loaded.package_name == "hello-2.12.2"


class TestTrackerCacheValidation:
    """Test tracker-side cache validation (Layer 2)."""

    def test_validate_cache_permissive_mode(self):
        """Test that validation is permissive when no allowed_caches configured."""
        import sqlite3
        from peerix.tracker import _validate_cache

        conn = sqlite3.connect(":memory:")
        conn.execute("""
            CREATE TABLE allowed_caches (
                cache_url TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                enabled INTEGER DEFAULT 1
            )
        """)

        # No allowed caches configured - should allow everything
        assert _validate_cache(conn, "https://any-cache.com")
        assert _validate_cache(conn, "https://another-cache.com", "any-key")

    def test_validate_cache_with_allowed_list(self):
        """Test validation when allowed_caches are configured."""
        import sqlite3
        from peerix.tracker import _validate_cache

        conn = sqlite3.connect(":memory:")
        conn.execute("""
            CREATE TABLE allowed_caches (
                cache_url TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                enabled INTEGER DEFAULT 1
            )
        """)
        conn.execute(
            "INSERT INTO allowed_caches VALUES (?, ?, ?)",
            ("https://cache.nixos.org", "cache.nixos.org-1:key", 1)
        )

        # Allowed cache
        assert _validate_cache(conn, "https://cache.nixos.org")
        assert _validate_cache(conn, "https://cache.nixos.org", "cache.nixos.org-1:key")

        # Not allowed
        assert not _validate_cache(conn, "https://evil-cache.com")
        assert not _validate_cache(conn, "https://cache.nixos.org", "wrong-key")


class TestCachesConfig:
    """Test caches configuration parsing."""

    def test_default_config(self):
        """Test default caches config."""
        from peerix.config import CachesConfig

        config = CachesConfig()
        assert config.default == "https://cache.nixos.org"
        assert config.auto_detect is True
        assert config.track_origins is True

    def test_config_with_trusted_caches(self):
        """Test config with additional trusted caches."""
        from peerix.config import CachesConfig, TrustedCache

        config = CachesConfig(
            trusted_caches=[
                TrustedCache(url="https://my-cache.com", public_key="my-cache-1:key")
            ]
        )
        assert len(config.trusted_caches) == 1
        assert config.trusted_caches[0].url == "https://my-cache.com"

    def test_load_config_with_caches_section(self):
        """Test loading config file with caches section."""
        from peerix.config import load_config
        import tempfile

        config_content = """
[caches]
default = "https://cache.nixos.org"
default_key = "cache.nixos.org-1:key"
auto_detect = false
track_origins = true

[[caches.trusted_caches]]
url = "https://my-cache.com"
public_key = "my-cache-1:abc123"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.toml', delete=False) as f:
            f.write(config_content)
            f.flush()

            config = load_config(Path(f.name))

            assert config.caches.default == "https://cache.nixos.org"
            assert config.caches.auto_detect is False
            assert config.caches.track_origins is True
            assert len(config.caches.trusted_caches) == 1
            assert config.caches.trusted_caches[0].url == "https://my-cache.com"

            os.unlink(f.name)


class TestPackageOriginPayload:
    """Test package origin payload generation for tracker sync."""

    def test_build_packages_with_origins(self):
        """Test building package list with origin metadata."""
        from peerix.iroh_app import StoreManager
        from peerix.origin_detector import OriginInfo

        manager = StoreManager(
            scan_interval=0,
            track_origins=True,
        )

        # Add some origins
        manager._package_origins["hash1"] = OriginInfo(
            cache_url="https://cache.nixos.org",
            public_key="cache.nixos.org-1:key",
            package_name="hello-2.12"
        )
        manager._package_origins["hash2"] = OriginInfo(
            cache_url="https://my-cache.com",
            public_key="my-cache-1:key2",
            package_name="curl-8.0"
        )

        # Build payload
        packages = manager._build_packages_with_origins(["hash1", "hash2", "hash3"])

        assert len(packages) == 3

        # hash1 should have origin
        pkg1 = next(p for p in packages if p["hash"] == "hash1")
        assert pkg1["origin"] == "https://cache.nixos.org"
        assert pkg1["public_key"] == "cache.nixos.org-1:key"
        assert pkg1["name"] == "hello-2.12"

        # hash3 should have no origin (not in _package_origins)
        pkg3 = next(p for p in packages if p["hash"] == "hash3")
        assert "origin" not in pkg3


class TestExtractDomain:
    """Test domain extraction helper."""

    def test_extract_domain_https(self):
        """Test extracting domain from HTTPS URL."""
        from peerix.cache_registry import _extract_domain
        assert _extract_domain("https://cache.nixos.org") == "cache.nixos.org"
        assert _extract_domain("https://cache.nixos.org/") == "cache.nixos.org"
        assert _extract_domain("https://cache.nixos.org/path") == "cache.nixos.org"

    def test_extract_domain_with_port(self):
        """Test extracting domain from URL with port."""
        from peerix.cache_registry import _extract_domain
        assert _extract_domain("https://localhost:8080") == "localhost"
        assert _extract_domain("http://127.0.0.1:12304") == "127.0.0.1"
