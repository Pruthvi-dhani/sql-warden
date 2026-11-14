"""Who is calling: a bearer token turned into an identity and the profile it gets.

Two kinds of token. An API key is a random string sql-warden made; the config keeps its
hash, the name of whoever holds it, and its profile. An OIDC token is a JWT from an identity
provider, checked against the keys the provider publishes; a claim, or the caller's groups,
name the profile.

A token that gives no profile is refused: it is never given default_profile, so a mistake
in the provider's setup can't quietly hand out a profile nobody chose.
"""

import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.request
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from typing import Any

import jwt

from sql_warden.config import SIGNING_ALGORITHMS, ApiKeyConfig, AuthConfig, OidcConfig
from sql_warden.models import RefusalCode

API_KEY_PREFIX = "swk_"
"""What an API key starts with, so one is easy to tell from a JWT, and to find if leaked."""
JWKS_REFRESH_S = 60.0
"""How often, at most, the provider's keys are fetched again for a token signed with one
that isn't known yet. A provider rotating its keys is seen within this; a stream of tokens
with made-up key ids costs it at most one fetch a minute."""
JWKS_MAX_AGE_S = 3600.0
"""How long fetched keys are used before they are fetched again anyway: a key the provider
withdrew stops being accepted within this."""
JWKS_TIMEOUT_S = 5.0
JWKS_MAX_BYTES = 1024 * 1024


_FAMILIES = {"RSA": ("RS", "PS"), "EC": ("ES",), "OKP": ("EdDSA",)}
"""The algorithms each type of key can check."""


@dataclass(frozen=True)
class SigningKey:
    key: Any
    """The public key itself."""
    type: str
    """The JWK's kty: RSA, EC or OKP."""
    algorithm: str | None
    """The one algorithm the provider says it signs with, if it says."""

    def checks(self, algorithm: str) -> bool:
        if self.algorithm is not None:
            return algorithm == self.algorithm
        return algorithm.startswith(_FAMILIES.get(self.type, ()))


@dataclass(frozen=True)
class Identity:
    name: str
    """Who the caller is, as the audit log records it: an API key's name, or oidc:<sub>."""
    profile: str


class AuthError(Exception):
    """A request that can't be let in. The message is safe to send back: it says what was
    wrong with the token, never anything about the keys or the other callers."""

    status = 401
    code = RefusalCode.UNAUTHENTICATED
    error = "invalid_token"
    """The OAuth error, for the WWW-Authenticate header."""

    def __init__(self, message: str, *, who: str | None = None) -> None:
        super().__init__(message)
        self.who = who
        """Who the token says the caller is, when it is genuine but gives no profile: the
        audit log records the refusal under that name."""


class NoProfile(AuthError):
    status = 403
    code = RefusalCode.NO_PROFILE
    error = "insufficient_scope"


class AuthUnavailable(AuthError):
    status = 503
    code = RefusalCode.AUTH_UNAVAILABLE
    error = "temporarily_unavailable"


def new_api_key() -> str:
    """A key nobody can guess: 256 random bits."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def key_hash(key: str) -> str:
    """What the config keeps of a key."""
    return hashlib.sha256(key.encode()).hexdigest()


Fetch = Callable[[str], bytes]


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=JWKS_TIMEOUT_S) as response:
        body: bytes = response.read(JWKS_MAX_BYTES + 1)
    if len(body) > JWKS_MAX_BYTES:
        raise ValueError(f"the key set is over {JWKS_MAX_BYTES:,} bytes")
    return body


class SigningKeys:
    """The provider's published keys, by key id: fetched when first needed, kept for an
    hour, and fetched again early (at most once a minute) for a key id not seen yet.
    Thread-safe: requests are checked in worker threads."""

    def __init__(
        self,
        url: str,
        *,
        fetch: Fetch = _fetch,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._fetch = fetch
        self._clock = clock
        self._keys: dict[str | None, SigningKey] = {}
        self._fetched_at: float | None = None
        self._lock = threading.Lock()

    def get(self, kid: str | None) -> SigningKey | None:
        with self._lock:
            now = self._clock()
            stale = self._fetched_at is None or now - self._fetched_at >= JWKS_MAX_AGE_S
            unknown = kid not in self._keys
            may_refresh = self._fetched_at is None or now - self._fetched_at >= JWKS_REFRESH_S
            if stale or (unknown and may_refresh):
                self._refresh(now)
            if kid is None and len(self._keys) == 1:
                return next(iter(self._keys.values()))  # a token may leave it out then
            return self._keys.get(kid)

    def _refresh(self, now: float) -> None:
        try:
            published = json.loads(self._fetch(self._url))
            keys = published.get("keys") if isinstance(published, dict) else None
            if not isinstance(keys, list):
                raise ValueError("it has no list of keys")
        except Exception as exc:
            if self._fetched_at is not None and now - self._fetched_at < JWKS_MAX_AGE_S:
                return  # keep what was fetched before, until it is too old to trust
            raise AuthUnavailable(
                "could not fetch the identity provider's keys to check the token"
            ) from exc
        usable: dict[str | None, SigningKey] = {}
        for entry in keys:
            if not isinstance(entry, dict) or entry.get("use", "sig") != "sig":
                continue  # not for signatures
            if entry.get("kty") not in _FAMILIES:
                continue  # a shared secret ("oct"), or a kind this server doesn't know
            try:
                key = jwt.PyJWK.from_dict(entry)
            except jwt.PyJWKError:
                continue  # one this server can't use; the others still count
            declared = entry.get("alg")
            usable[key.key_id] = SigningKey(
                key.key, str(entry["kty"]), declared if isinstance(declared, str) else None
            )
        self._keys, self._fetched_at = usable, now


class Authenticator:
    """Turns a bearer token into an Identity, or raises AuthError."""

    def __init__(
        self,
        config: AuthConfig,
        profiles: Collection[str],
        *,
        fetch: Fetch = _fetch,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._keys: tuple[ApiKeyConfig, ...] = config.api_keys
        self._oidc = config.oidc
        self._profiles = frozenset(profiles)
        self._signing = (
            None
            if config.oidc is None
            else SigningKeys(config.oidc.jwks_url, fetch=fetch, clock=clock)
        )

    @property
    def issuer(self) -> str | None:
        return None if self._oidc is None else self._oidc.issuer

    def authenticate(self, token: str) -> Identity:
        if token.startswith(API_KEY_PREFIX):
            return self._api_key(token)
        if self._oidc is None:
            raise AuthError("unknown API key")
        return self._jwt(token, self._oidc)

    def _api_key(self, token: str) -> Identity:
        digest = key_hash(token)
        found = None
        for key in self._keys:  # every one, so the time taken doesn't say which matched
            if hmac.compare_digest(digest, key.sha256):
                found = key
        if found is None:
            raise AuthError("unknown API key")
        return self._identity(found.name, found.profile)

    def _jwt(self, token: str, oidc: OidcConfig) -> Identity:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("not a token this server can read") from exc
        algorithm = header.get("alg")
        if algorithm not in oidc.algorithms:
            # Named only if it is one: the header is the caller's to write.
            named = algorithm if algorithm in (*SIGNING_ALGORITHMS, "none", "HS256") else None
            raise AuthError(f"tokens signed with {named or 'that algorithm'} are not accepted")
        assert self._signing is not None
        key = self._signing.get(header.get("kid"))
        if key is None:
            raise AuthError("the token is signed with a key the identity provider doesn't list")
        if not key.checks(algorithm):
            raise AuthError("the token's algorithm is not the one its key is for")
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[algorithm],
                audience=oidc.audience,
                issuer=oidc.issuer,
                leeway=oidc.leeway_s,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("the token has expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthError("the token is not valid yet") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("the token is for another service") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("the token is from another identity provider") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthError(f"the token has no {exc.claim} claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError("the token's signature does not check out") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("the token is not valid") from exc
        subject = claims["sub"]
        if not isinstance(subject, str) or not subject or len(subject) > 255:
            raise AuthError("the token's sub claim is not a name")
        name = f"oidc:{subject}"
        try:
            profile = self._profile_of(claims, oidc)
        except NoProfile as exc:
            exc.who = name
            raise
        return self._identity(name, profile)

    def _profile_of(self, claims: Mapping[str, Any], oidc: OidcConfig) -> str:
        if oidc.group_profiles:
            groups = claims.get(oidc.group_claim)
            if isinstance(groups, str):
                groups = [groups]
            if not isinstance(groups, list):
                raise NoProfile(f"the token lists no groups in its {oidc.group_claim} claim")
            given = sorted(
                {
                    oidc.group_profiles[g]
                    for g in groups
                    if isinstance(g, str) and g in oidc.group_profiles
                }
            )
            if not given:
                raise NoProfile("none of the token's groups gives a profile")
            if len(given) > 1:
                raise NoProfile(
                    f"the token's groups give more than one profile ({', '.join(given)}); "
                    "a caller gets exactly one"
                )
            return given[0]
        profile = claims.get(oidc.profile_claim)
        if not isinstance(profile, str) or not profile:
            raise NoProfile(f"the token names no profile in its {oidc.profile_claim} claim")
        return profile

    def _identity(self, name: str, profile: str) -> Identity:
        if profile not in self._profiles:
            raise NoProfile(
                f"the token gives the profile {profile[:64]!r}, which this server doesn't have",
                who=name,
            )
        return Identity(name, profile)
