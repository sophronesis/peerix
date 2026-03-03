"""
Core unit tests for Peerix.

Run with: pytest peerix/tests/
"""
import pytest
import time
from pathlib import Path


class TestNarHash:
    """Test NAR hash computation."""

    def test_compute_nar_hash_empty(self):
        """Test hash of empty data."""
        from peerix.iroh_app import compute_nar_hash
        result = compute_nar_hash(b"")
        assert result.startswith("sha256:")
        assert len(result) == 59  # "sha256:" (7) + 52 base32 chars

    def test_compute_nar_hash_known_value(self):
        """Test hash computation produces consistent results."""
        from peerix.iroh_app import compute_nar_hash
        data = b"test data for hashing"
        hash1 = compute_nar_hash(data)
        hash2 = compute_nar_hash(data)
        assert hash1 == hash2

    def test_compute_nar_hash_different_data(self):
        """Test that different data produces different hashes."""
        from peerix.iroh_app import compute_nar_hash
        hash1 = compute_nar_hash(b"data1")
        hash2 = compute_nar_hash(b"data2")
        assert hash1 != hash2

    def test_verify_nar_hash_valid(self):
        """Test hash verification with matching data."""
        from peerix.iroh_app import compute_nar_hash, verify_nar_hash
        data = b"test data"
        hash_value = compute_nar_hash(data)
        assert verify_nar_hash(data, hash_value) is True

    def test_verify_nar_hash_invalid(self):
        """Test hash verification with mismatched data."""
        from peerix.iroh_app import compute_nar_hash, verify_nar_hash
        data = b"test data"
        hash_value = compute_nar_hash(b"different data")
        assert verify_nar_hash(data, hash_value) is False

    def test_verify_nar_hash_unsupported_format(self):
        """Test hash verification with unsupported format."""
        from peerix.iroh_app import verify_nar_hash
        assert verify_nar_hash(b"data", "md5:abc123") is False


class TestPathValidation:
    """Test Nix store path validation."""

    def test_validate_store_path_valid(self):
        """Test valid Nix store path."""
        from peerix.local import validate_store_path
        # Valid 32-char base32 hash + name
        valid_path = "/nix/store/0123456789abcdfghjklmnpqrstvwxyz-test-pkg"
        assert validate_store_path(valid_path) is True

    def test_validate_store_path_invalid_prefix(self):
        """Test path with invalid prefix."""
        from peerix.local import validate_store_path
        assert validate_store_path("/home/user/test") is False
        assert validate_store_path("/nix/var/test") is False

    def test_validate_store_path_short_hash(self):
        """Test path with too-short hash."""
        from peerix.local import validate_store_path
        assert validate_store_path("/nix/store/abc-test") is False

    def test_validate_store_path_invalid_chars(self):
        """Test path with invalid characters in hash."""
        from peerix.local import validate_store_path
        # 'e' is not in Nix base32 alphabet
        invalid_path = "/nix/store/0123456789abcdefghijklmnopqrstuv-test"
        assert validate_store_path(invalid_path) is False

    def test_validate_store_path_traversal_attempt(self):
        """Test path with directory traversal."""
        from peerix.local import validate_store_path
        assert validate_store_path("/nix/store/../etc/passwd") is False
        assert validate_store_path("/nix/store/./test") is False


class TestPeerReputation:
    """Test peer reputation system."""

    def test_reputation_initial_score(self):
        """Test initial reputation score for new peer."""
        from peerix.iroh_proto import PeerReputation
        rep = PeerReputation()
        # New peer has neutral success rate
        assert rep.success_rate == 0.5
        score = rep.score()
        assert 0 <= score <= 1

    def test_reputation_after_success(self):
        """Test reputation improves after success."""
        from peerix.iroh_proto import PeerReputation
        rep = PeerReputation()
        rep.record_success(bytes_transferred=1000, latency_ms=50)
        assert rep.success_rate == 1.0
        assert rep.total_requests == 1
        assert rep.successful_requests == 1
        assert not rep.is_backed_off()

    def test_reputation_after_failure(self):
        """Test reputation degrades after failure."""
        from peerix.iroh_proto import PeerReputation
        rep = PeerReputation()
        backoff = rep.record_failure(latency_ms=5000)
        assert rep.success_rate == 0.0
        assert rep.failed_requests == 1
        assert backoff > 0
        assert rep.is_backed_off()

    def test_reputation_backoff_exponential(self):
        """Test backoff increases exponentially."""
        from peerix.iroh_proto import PeerReputation
        rep = PeerReputation()
        backoff1 = rep.record_failure()
        # Reset for next test
        rep.backoff_until = 0
        backoff2 = rep.record_failure()
        assert backoff2 > backoff1

    def test_reputation_score_comparison(self):
        """Test that reliable peers score higher."""
        from peerix.iroh_proto import PeerReputation
        good_peer = PeerReputation()
        bad_peer = PeerReputation()

        # Good peer: many successes, low latency
        for _ in range(10):
            good_peer.record_success(latency_ms=50)

        # Bad peer: many failures
        for _ in range(10):
            bad_peer.record_failure()
            bad_peer.backoff_until = 0  # Reset backoff for fair comparison

        assert good_peer.score() > bad_peer.score()


class TestConfig:
    """Test configuration loading."""

    def test_load_config_missing_file(self, tmp_path):
        """Test loading config when file doesn't exist."""
        from peerix.config import load_config, PeerixConfig
        config = load_config(tmp_path / "nonexistent.toml", create_if_missing=False)
        assert isinstance(config, PeerixConfig)
        # Should return defaults
        assert config.server.port == 12304

    def test_load_config_create_default(self, tmp_path):
        """Test creating default config file."""
        from peerix.config import load_config
        config_path = tmp_path / "config.toml"
        config = load_config(config_path, create_if_missing=True)
        assert config_path.exists()
        assert config.server.port == 12304

    def test_load_config_custom_values(self, tmp_path):
        """Test loading config with custom values."""
        from peerix.config import load_config
        config_path = tmp_path / "config.toml"
        config_path.write_text("""
[server]
port = 9999
priority = 1

[tracker]
url = "https://example.com/tracker"

[store]
scan_interval = 7200
""")
        config = load_config(config_path)
        assert config.server.port == 9999
        assert config.server.priority == 1
        assert config.tracker.url == "https://example.com/tracker"
        assert config.store.scan_interval == 7200


class TestKalmanETA:
    """Test Kalman filter ETA estimation."""

    def test_kalman_initial_estimate(self):
        """Test initial ETA when no data available."""
        from peerix.iroh_app import KalmanETA
        eta = KalmanETA()
        result = eta.update(0, 100)
        assert result is None  # Not enough data yet

    def test_kalman_with_data(self):
        """Test ETA after processing some items."""
        from peerix.iroh_app import KalmanETA
        eta = KalmanETA()
        # First update initializes
        eta.update(0, 100)
        time.sleep(0.2)
        # Second update can compute rate
        result = eta.update(10, 100)
        # Should have an estimate now
        assert result is None or result > 0

    def test_kalman_format_seconds(self):
        """Test ETA formatting for seconds."""
        from peerix.iroh_app import KalmanETA
        eta = KalmanETA()
        assert eta.format_eta(30) == "30s"
        assert eta.format_eta(59) == "59s"

    def test_kalman_format_minutes(self):
        """Test ETA formatting for minutes."""
        from peerix.iroh_app import KalmanETA
        eta = KalmanETA()
        assert "m" in eta.format_eta(120)
        assert "m" in eta.format_eta(3599)

    def test_kalman_format_hours(self):
        """Test ETA formatting for hours."""
        from peerix.iroh_app import KalmanETA
        eta = KalmanETA()
        assert "h" in eta.format_eta(3600)
        assert "h" in eta.format_eta(7200)


class TestMetrics:
    """Test metrics recording."""

    def test_record_metric_counter(self):
        """Test counter metric increment."""
        from peerix.iroh_app import _record_metric, _metrics
        initial = _metrics.get("cache_hits_total", 0)
        _record_metric("cache_hits_total", 1)
        assert _metrics["cache_hits_total"] == initial + 1

    def test_record_metric_histogram(self):
        """Test histogram metric recording."""
        from peerix.iroh_app import _record_metric, _metrics
        _record_metric("request_duration_seconds", 0.5, {"type": "test"})
        assert len(_metrics["request_duration_seconds"]) > 0


class TestHealthState:
    """Test health state tracking."""

    def test_health_state_initial(self):
        """Test initial health state."""
        from peerix.iroh_app import _health_state
        assert "start_time" in _health_state
        assert _health_state["errors_count"] >= 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
