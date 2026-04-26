"""Unit tests for auth_service — pure functions, no DB or HTTP."""

import pytest
from jose import JWTError

from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
)


class TestHashPassword:
    def test_returns_pbkdf2_hash(self):
        assert hash_password("mypassword").startswith("$pbkdf2-sha256$")

    def test_different_hash_each_call(self):
        # Salted — two hashes of the same password must differ
        assert hash_password("same") != hash_password("same")

    def test_empty_password(self):
        h = hash_password("")
        assert h.startswith("$pbkdf2-sha256$")


class TestVerifyPassword:
    def test_correct_password(self):
        hashed = hash_password("correcthorsebatterystaple")
        assert verify_password("correcthorsebatterystaple", hashed) is True

    def test_wrong_password(self):
        hashed = hash_password("correctpass")
        assert verify_password("wrongpass", hashed) is False

    def test_invalid_hash_format_returns_false(self):
        # Should not raise — returns False for unrecognised hash format
        assert verify_password("anything", "not-a-real-hash") is False

    def test_empty_password_against_empty_hash(self):
        hashed = hash_password("")
        assert verify_password("", hashed) is True


class TestCreateAccessToken:
    def test_contains_expected_claims(self):
        data = {"sub": "user-123", "email": "test@sqb.uz", "role": "analyst"}
        payload = decode_token(create_access_token(data))

        assert payload["sub"] == "user-123"
        assert payload["email"] == "test@sqb.uz"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"
        assert "exp" in payload

    def test_type_is_access(self):
        payload = decode_token(create_access_token({"sub": "x"}))
        assert payload["type"] == "access"


class TestCreateRefreshToken:
    def test_type_is_refresh(self):
        payload = decode_token(create_refresh_token({"sub": "x"}))
        assert payload["type"] == "refresh"

    def test_expires_later_than_access_token(self):
        data = {"sub": "user-123"}
        access_exp = decode_token(create_access_token(data))["exp"]
        refresh_exp = decode_token(create_refresh_token(data))["exp"]
        assert refresh_exp > access_exp


class TestDecodeToken:
    def test_valid_token(self):
        token = create_access_token({"sub": "abc"})
        assert decode_token(token)["sub"] == "abc"

    def test_invalid_signature_raises(self):
        token = create_access_token({"sub": "abc"})
        parts = token.split(".")
        bad_token = f"{parts[0]}.{parts[1]}.invalidsignature"
        with pytest.raises(JWTError):
            decode_token(bad_token)

    def test_malformed_token_raises(self):
        with pytest.raises(Exception):
            decode_token("not.a.jwt")

    def test_completely_random_string_raises(self):
        with pytest.raises(Exception):
            decode_token("randomstring")
