"""Tokens turned into callers: API keys, and OIDC tokens checked against a provider's keys.

The provider is a stand-in: keys made here, published as a JWKS document that `fetch`
returns, so nothing leaves the machine and its clock can be moved.
"""

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from sql_warden.auth import (
    API_KEY_PREFIX,
    JWKS_MAX_AGE_S,
    JWKS_REFRESH_S,
    Authenticator,
    AuthError,
    AuthUnavailable,
    Identity,
    key_hash,
    new_api_key,
)
from sql_warden.config import AuthConfig, ConfigError, parse_config
from sql_warden.models import RefusalCode

ISSUER = "https://idp.example.com/"
AUDIENCE = "sql-warden"
JWKS_URL = "https://idp.example.com/.well-known/jwks.json"
PROFILES = ("public", "support", "admin")
SUPPORT_KEY = new_api_key()
ADMIN_KEY = new_api_key()


def _rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNER = _rsa()
OTHER = _rsa()
EC_SIGNER = ec.generate_private_key(ec.SECP256R1())


def _jwk(key: Any, kid: str, **extra: str) -> dict[str, Any]:
    if isinstance(key, rsa.RSAPrivateKey):
        public: dict[str, Any] = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    else:
        public = ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
    return {**public, "kid": kid, **extra}


@dataclass
class Provider:
    """The identity provider's published keys, and a clock to move."""

    keys: list[dict[str, Any]] = field(default_factory=lambda: [_jwk(SIGNER, "k1")])
    now: float = 1_000.0
    fetched: int = 0
    down: bool = False

    def fetch(self, url: str) -> bytes:
        assert url == JWKS_URL
        self.fetched += 1
        if self.down:
            raise OSError("connection refused")
        return json.dumps({"keys": self.keys}).encode()

    def clock(self) -> float:
        return self.now


def _config(oidc: dict[str, Any] | None = None, **auth: Any) -> AuthConfig:
    fields: dict[str, Any] = {
        "api_keys": [
            {"name": "support-bot", "profile": "support", "sha256": key_hash(SUPPORT_KEY)},
            {"name": "ops", "profile": "admin", "sha256": key_hash(ADMIN_KEY)},
        ],
        **auth,
    }
    if oidc is not None:
        fields["oidc"] = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_url": JWKS_URL,
            **oidc,
        }
    return AuthConfig.model_validate(fields)


def _authenticator(
    provider: Provider | None = None, oidc: dict[str, Any] | None = None, **auth: Any
) -> Authenticator:
    provider = provider or Provider()
    return Authenticator(
        _config({} if oidc is None else oidc, **auth),
        PROFILES,
        fetch=provider.fetch,
        clock=provider.clock,
    )


def _token(
    key: Any = SIGNER,
    *,
    kid: str | None = "k1",
    algorithm: str = "RS256",
    drop: tuple[str, ...] = (),
    **claims: Any,
) -> str:
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-42",
        "iat": now,
        "exp": now + 300,
        "sql_warden_profile": "support",
        **claims,
    }
    for name in drop:
        payload.pop(name)
    headers = {} if kid is None else {"kid": kid}
    return jwt.encode(payload, key, algorithm=algorithm, headers=headers)


def _forged(header: dict[str, str], secret: bytes) -> str:
    """A token made by hand, as an attacker would: pyjwt won't make these."""
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "x",
        "exp": now + 60,
        "sql_warden_profile": "admin",
    }
    signing_input = b".".join(
        jwt.utils.base64url_encode(json.dumps(part).encode()) for part in (header, payload)
    )
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest() if secret else b""
    return (signing_input + b"." + jwt.utils.base64url_encode(signature)).decode()


def _refused(authenticator: Authenticator, token: str) -> AuthError:
    with pytest.raises(AuthError) as excinfo:
        authenticator.authenticate(token)
    return excinfo.value


class TestApiKeys:
    def test_a_key_gives_its_holder_and_profile(self) -> None:
        authenticator = _authenticator()
        assert authenticator.authenticate(SUPPORT_KEY) == Identity("support-bot", "support")
        assert authenticator.authenticate(ADMIN_KEY) == Identity("ops", "admin")

    def test_an_unknown_key(self) -> None:
        refused = _refused(_authenticator(), new_api_key())
        assert (refused.status, refused.code, str(refused)) == (
            401,
            RefusalCode.UNAUTHENTICATED,
            "unknown API key",
        )
        assert refused.who is None

    @pytest.mark.parametrize(
        "token",
        [
            SUPPORT_KEY[:-1],
            SUPPORT_KEY + "x",
            SUPPORT_KEY.upper(),
            key_hash(SUPPORT_KEY),  # the hash from the config is not the key
            API_KEY_PREFIX,
        ],
    )
    def test_anything_but_the_key_itself(self, token: str) -> None:
        assert _refused(_authenticator(), token).status == 401

    def test_without_oidc_a_jwt_is_just_an_unknown_key(self) -> None:
        authenticator = Authenticator(_config(), PROFILES)
        assert str(_refused(authenticator, _token())) == "unknown API key"

    def test_keys_are_random_and_only_their_hash_is_kept(self) -> None:
        keys = {new_api_key() for _ in range(100)}
        assert len(keys) == 100
        assert all(key.startswith(API_KEY_PREFIX) and len(key) > 40 for key in keys)
        assert key_hash(SUPPORT_KEY) != SUPPORT_KEY
        assert len(key_hash(SUPPORT_KEY)) == 64

    def test_a_key_whose_profile_the_server_lost(self) -> None:
        # The config check prevents it; the authenticator still refuses rather than guess.
        authenticator = Authenticator(_config(), ("public",))
        refused = _refused(authenticator, SUPPORT_KEY)
        assert (refused.status, refused.who) == (403, "support-bot")


class TestOidc:
    def test_a_valid_token(self) -> None:
        assert _authenticator().authenticate(_token()) == Identity("oidc:user-42", "support")

    def test_an_ec_key(self) -> None:
        provider = Provider(keys=[_jwk(EC_SIGNER, "ec1")])
        token = _token(EC_SIGNER, kid="ec1", algorithm="ES256")
        assert _authenticator(provider).authenticate(token).profile == "support"

    @pytest.mark.parametrize(
        ("token", "reason"),
        [
            (_token(exp=int(time.time()) - 120), "the token has expired"),
            (_token(nbf=int(time.time()) + 600), "the token is not valid yet"),
            (_token(aud="another-service"), "the token is for another service"),
            (
                _token(iss="https://evil.example.com/"),
                "the token is from another identity provider",
            ),
            (_token(drop=("exp",)), "the token has no exp claim"),
            (_token(drop=("sub",)), "the token has no sub claim"),
            (_token(drop=("aud",)), "the token has no aud claim"),
            (_token(sub=""), "the token's sub claim is not a name"),
            (_token(sub="x" * 300), "the token's sub claim is not a name"),
            (_token(OTHER), "the token's signature does not check out"),
            (_token(kid="k9"), "the token is signed with a key the identity provider doesn't list"),
            ("not.a.token", "not a token this server can read"),
            ("abc", "not a token this server can read"),
        ],
    )
    def test_a_token_that_is_not_valid(self, token: str, reason: str) -> None:
        refused = _refused(_authenticator(), token)
        assert (refused.status, refused.code, str(refused)) == (
            401,
            RefusalCode.UNAUTHENTICATED,
            reason,
        )

    def test_an_expired_token_within_the_leeway_is_still_good(self) -> None:
        token = _token(exp=int(time.time()) - 10)
        assert _authenticator().authenticate(token).name == "oidc:user-42"
        refused = _refused(_authenticator(oidc={"leeway_s": 0}), token)
        assert str(refused) == "the token has expired"

    def test_unsigned_tokens_are_refused(self) -> None:
        unsigned = _forged({"alg": "none", "kid": "k1"}, b"")
        assert str(_refused(_authenticator(), unsigned)) == (
            "tokens signed with none are not accepted"
        )

    def test_a_token_signed_with_the_public_key_as_a_shared_secret(self) -> None:
        # The classic confusion: HS256 "signed" with the provider's public key, which
        # anyone can download. Only public-key algorithms are accepted.
        public = SIGNER.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        forged = _forged({"alg": "HS256", "kid": "k1"}, public)
        assert str(_refused(_authenticator(), forged)) == (
            "tokens signed with HS256 are not accepted"
        )
        # Nor can a config allow it.
        with pytest.raises(ConfigError, match="HS256 is not allowed"):
            _parsed(
                f"  oidc:\n    issuer: {ISSUER}\n    audience: a\n    jwks_url: {JWKS_URL}\n"
                "    algorithms: [HS256]\n"
            )

    def test_a_shared_secret_in_the_key_set_is_never_used(self) -> None:
        secret = {"kty": "oct", "kid": "k1", "k": "c2VjcmV0"}
        provider = Provider(keys=[secret])
        assert "doesn't list" in str(_refused(_authenticator(provider), _token()))

    def test_a_key_is_only_used_with_its_own_algorithm(self) -> None:
        # An RSA key can't check an EC signature, and one the provider pins to RS256 only
        # that.
        provider = Provider(keys=[_jwk(SIGNER, "k1", alg="RS256")])
        authenticator = _authenticator(provider, oidc={"algorithms": ["RS256", "RS512"]})
        assert str(_refused(authenticator, _token(algorithm="RS512"))) == (
            "the token's algorithm is not the one its key is for"
        )
        ec_signed = _token(EC_SIGNER, kid="k1", algorithm="ES256")
        assert str(_refused(_authenticator(), ec_signed)) == (
            "the token's algorithm is not the one its key is for"
        )

    def test_an_algorithm_the_config_doesnt_list(self) -> None:
        token = _token(algorithm="RS512")
        assert str(_refused(_authenticator(), token)) == "tokens signed with RS512 are not accepted"
        allowed = _authenticator(oidc={"algorithms": ["RS512"]})
        assert allowed.authenticate(token).profile == "support"

    def test_a_made_up_algorithm_is_not_repeated_back(self) -> None:
        header = jwt.utils.base64url_encode(json.dumps({"alg": 'x", evil="1'}).encode())
        token = header.decode() + ".e30.c2ln"
        assert str(_refused(_authenticator(), token)) == (
            "tokens signed with that algorithm are not accepted"
        )

    def test_a_key_kept_for_encryption_is_not_used_to_check_signatures(self) -> None:
        provider = Provider(keys=[_jwk(SIGNER, "k1", use="enc")])
        assert "doesn't list" in str(_refused(_authenticator(provider), _token()))

    def test_without_a_kid_the_only_key_is_used(self) -> None:
        assert _authenticator().authenticate(_token(kid=None)).profile == "support"
        two = Provider(keys=[_jwk(SIGNER, "k1"), _jwk(OTHER, "k2")])
        assert "doesn't list" in str(_refused(_authenticator(two), _token(kid=None)))


class TestProfileFromTheToken:
    @pytest.mark.parametrize(
        ("claims", "reason"),
        [
            (
                {"sql_warden_profile": None},
                "the token names no profile in its sql_warden_profile claim",
            ),
            (
                {"sql_warden_profile": ""},
                "the token names no profile in its sql_warden_profile claim",
            ),
            (
                {"sql_warden_profile": ["admin"]},
                "the token names no profile in its sql_warden_profile claim",
            ),
            (
                {"sql_warden_profile": "root"},
                "the token gives the profile 'root', which this server doesn't have",
            ),
        ],
    )
    def test_no_profile_is_refused_never_defaulted(
        self, claims: dict[str, Any], reason: str
    ) -> None:
        refused = _refused(_authenticator(), _token(**claims))
        assert (refused.status, refused.code, str(refused)) == (403, RefusalCode.NO_PROFILE, reason)
        # A real caller, so the refusal is recorded under their name.
        assert refused.who == "oidc:user-42"

    def test_another_claim(self) -> None:
        authenticator = _authenticator(oidc={"profile_claim": "warden"})
        assert authenticator.authenticate(_token(warden="admin")).profile == "admin"

    def test_by_group(self) -> None:
        authenticator = _authenticator(
            oidc={"group_profiles": {"analysts": "support", "dba": "admin", "admins": "admin"}}
        )
        assert authenticator.authenticate(_token(groups=["staff", "analysts"])).profile == "support"
        assert authenticator.authenticate(_token(groups="dba")).profile == "admin"
        # Two groups for the same profile are one profile.
        assert authenticator.authenticate(_token(groups=["dba", "admins"])).profile == "admin"
        # The claim naming a profile is not looked at once groups decide.
        assert (
            authenticator.authenticate(
                _token(groups=["analysts"], sql_warden_profile="admin")
            ).profile
            == "support"
        )

    @pytest.mark.parametrize(
        ("groups", "reason"),
        [
            (
                ["analysts", "dba"],
                "the token's groups give more than one profile (admin, support); "
                "a caller gets exactly one",
            ),
            (["staff"], "none of the token's groups gives a profile"),
            ([], "none of the token's groups gives a profile"),
            (None, "the token lists no groups in its groups claim"),
            ({"dba": True}, "the token lists no groups in its groups claim"),
        ],
    )
    def test_groups_that_dont_give_exactly_one(self, groups: Any, reason: str) -> None:
        authenticator = _authenticator(
            oidc={"group_profiles": {"analysts": "support", "dba": "admin"}}
        )
        refused = _refused(authenticator, _token(groups=groups))
        assert (refused.status, str(refused)) == (403, reason)


class TestTheProvidersKeys:
    def test_they_are_fetched_once_and_kept(self) -> None:
        provider = Provider()
        authenticator = _authenticator(provider)
        for _ in range(5):
            authenticator.authenticate(_token())
        assert provider.fetched == 1

    def test_a_new_key_is_picked_up_after_the_provider_rotates(self) -> None:
        provider = Provider()
        authenticator = _authenticator(provider)
        authenticator.authenticate(_token())
        provider.keys.append(_jwk(OTHER, "k2"))
        # Within a minute of the last fetch, an unknown key id doesn't fetch again...
        provider.now += JWKS_REFRESH_S - 1
        assert "doesn't list" in str(_refused(authenticator, _token(OTHER, kid="k2")))
        assert provider.fetched == 1
        # ...after it, it does.
        provider.now += 2
        assert authenticator.authenticate(_token(OTHER, kid="k2")).name == "oidc:user-42"
        assert provider.fetched == 2

    def test_made_up_key_ids_cost_the_provider_one_fetch_a_minute(self) -> None:
        provider = Provider()
        authenticator = _authenticator(provider)
        for n in range(50):
            _refused(authenticator, _token(kid=f"made-up-{n}"))
            provider.now += 1
        assert provider.fetched == 1

    def test_a_withdrawn_key_stops_working_within_the_hour(self) -> None:
        provider = Provider(keys=[_jwk(SIGNER, "k1"), _jwk(OTHER, "k2")])
        authenticator = _authenticator(provider)
        authenticator.authenticate(_token(OTHER, kid="k2"))
        provider.keys = [_jwk(SIGNER, "k1")]
        provider.now += JWKS_MAX_AGE_S
        assert "doesn't list" in str(_refused(authenticator, _token(OTHER, kid="k2")))

    def test_a_provider_that_cant_be_reached(self) -> None:
        provider = Provider(down=True)
        refused = _refused(_authenticator(provider), _token())
        assert isinstance(refused, AuthUnavailable)
        assert (refused.status, refused.code, str(refused)) == (
            503,
            RefusalCode.AUTH_UNAVAILABLE,
            "could not fetch the identity provider's keys to check the token",
        )

    def test_one_that_goes_down_after_answering_keeps_its_keys_for_the_hour(self) -> None:
        provider = Provider()
        authenticator = _authenticator(provider)
        authenticator.authenticate(_token())
        provider.down = True
        provider.now += JWKS_MAX_AGE_S - 1
        assert authenticator.authenticate(_token()).profile == "support"
        provider.now += 2
        assert isinstance(_refused(authenticator, _token()), AuthUnavailable)

    @pytest.mark.parametrize("published", [b"not json", b"[]", b'{"keys": "k1"}'])
    def test_a_key_set_it_cant_read(self, published: bytes) -> None:
        authenticator = Authenticator(
            _config({}), PROFILES, fetch=lambda url: published, clock=lambda: 0.0
        )
        assert isinstance(_refused(authenticator, _token()), AuthUnavailable)

    def test_api_keys_need_no_provider(self) -> None:
        provider = Provider(down=True)
        assert _authenticator(provider).authenticate(SUPPORT_KEY).profile == "support"
        assert provider.fetched == 0


def _parsed(auth: str, **extra: str) -> Any:
    text = (
        "version: 1\n"
        "profiles:\n  public:\n    tables: {}\n  support:\n    tables: {}\n"
        f"auth:\n{auth}"
    )
    for key, value in extra.items():
        text += f"{key}:\n{value}"
    return parse_config(text)


DIGEST = "a" * 64


class TestConfig:
    def test_api_keys_and_oidc(self) -> None:
        config = _parsed(
            f"  api_keys:\n    - {{name: bot, profile: support, sha256: {DIGEST.upper()}}}\n"
            f"  oidc:\n    issuer: {ISSUER}\n    audience: {AUDIENCE}\n    jwks_url: {JWKS_URL}\n"
        )
        assert config.auth.api_keys[0].sha256 == DIGEST
        assert config.auth.oidc.algorithms == ("RS256", "ES256")

    @pytest.mark.parametrize(
        ("auth", "problem"),
        [
            ("  {}\n", "give api_keys, oidc, or both"),
            (
                "  api_keys:\n    - {name: bot, profile: nobody, sha256: " + DIGEST + "}\n",
                "auth gives api key bot the profile 'nobody', "
                "but the config defines public, support",
            ),
            (
                "  api_keys:\n    - {name: bot, profile: support, sha256: swk_abc}\n",
                "must be the key's SHA-256 as 64 hex digits",
            ),
            (
                "  api_keys:\n    - {name: 'a b', profile: support, sha256: " + DIGEST + "}\n",
                "a key's name is up to 64 letters",
            ),
            (
                "  api_keys:\n    - {name: 'OIDC:ana', profile: support, sha256: " + DIGEST + "}\n",
                "a key's name can't start with oidc:",
            ),
            (
                "  api_keys:\n    - {name: bot, profile: support, sha256: " + DIGEST + "}\n"
                "    - {name: bot, profile: public, sha256: " + "b" * 64 + "}\n",
                "api_keys repeat names: bot",
            ),
            (
                "  api_keys:\n    - {name: one, profile: support, sha256: " + DIGEST + "}\n"
                "    - {name: two, profile: public, sha256: " + DIGEST + "}\n",
                "api_keys repeat hashes",
            ),
            (
                "  oidc:\n    issuer: http://idp.example.com/\n    audience: a\n"
                f"    jwks_url: {JWKS_URL}\n",
                "issuer must be an https:// URL",
            ),
            (
                f"  oidc:\n    issuer: {ISSUER}\n    audience: a\n    jwks_url: http://idp.example.com/keys\n",
                "jwks_url must be an https:// URL",
            ),
            (
                f"  oidc:\n    issuer: {ISSUER}\n    audience: a\n    jwks_url: {JWKS_URL}\n"
                "    algorithms: [HS256]\n",
                "HS256 is not allowed: only public-key signatures",
            ),
            (
                f"  oidc:\n    issuer: {ISSUER}\n    audience: a\n    jwks_url: {JWKS_URL}\n"
                "    algorithms: [none]\n",
                "none is not allowed",
            ),
            (
                f"  oidc:\n    issuer: {ISSUER}\n    audience: a\n    jwks_url: {JWKS_URL}\n"
                "    group_profiles: {dba: root}\n",
                "auth gives oidc group dba the profile 'root'",
            ),
        ],
    )
    def test_problems(self, auth: str, problem: str) -> None:
        with pytest.raises(ConfigError, match=problem.replace("(", r"\(").replace(")", r"\)")):
            _parsed(auth)

    def test_auth_needs_profiles(self) -> None:
        with pytest.raises(ConfigError, match="there is no profiles section"):
            parse_config(
                "version: 1\nauth:\n  api_keys:\n    - {name: b, profile: all, sha256: "
                + DIGEST
                + "}\n"
            )

    def test_http_on_this_machine_is_allowed_for_a_local_provider(self) -> None:
        config = _parsed(
            "  oidc:\n    issuer: http://127.0.0.1:9000/\n    audience: a\n"
            "    jwks_url: http://localhost:9000/keys\n"
        )
        assert config.auth.oidc.issuer == "http://127.0.0.1:9000/"
