"""Module providing sha primitives unit tests."""

import pytest
import json
from crypto.sha import sha3_224, sha3_256, sha3_512

class TestCryptoMethods:
    @pytest.mark.parametrize("i, expected_hash", [
        ("hello", "b87f88c72702fff1748e58b87e9141a42c0dbedc29a78cb0d4a5cd81"),
        ("world", "cd7b2b8e2d55948edcc4811388ab3915f26df12e6b7a39f744efdb95"),
        ("test", "3797bf0afbbfca4a7bbba7602a2b552746876517a7f9b7ce2db0ae7b"),
    ])
    def test_sha3_224(self, i, expected_hash):
        assert sha3_224(self, i) == json.dumps({'hash': expected_hash})

    @pytest.mark.parametrize("i, expected_hash", [
        ("hello", "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"),
        ("world", "420baf620e3fcd9b3715b42b92506e9304d56e02d3a103499a3a292560cb66b2"),
        ("test", "36f028580bb02cc8272a9a020f4200e346e276ae664e45ee80745574e2f5ab80"),
    ])
    def test_sha3_256(self, i, expected_hash):
        assert sha3_256(self, i) == json.dumps({'hash': expected_hash})

    @pytest.mark.parametrize("i, expected_hash", [
        ("hello", "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976"),
        ("world", "6ec5025ab9e3f5c74d15fb95404746c24ff11d3a4b597e2eab26f938d42aa2fd2a47e2e48e314372d129a5b6db88e63e315bb99273612641da44630d842fb6d9"),
        ("test", "9ece086e9bac491fac5c1d1046ca11d737b92a2b2ebd93f005d7b710110c0a678288166e7fbe796883a4f2e9b3ca9f484f521d0ce464345cc1aec96779149c14"),
    ])
    def test_sha3_512(self, i, expected_hash):
        assert sha3_512(self, i) == json.dumps({'hash': expected_hash})

if __name__ == "__main__":
    pytest.main([__file__])