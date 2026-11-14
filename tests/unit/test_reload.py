"""The policy against the live catalog (`config validate --live`, and a server's start), and
the policy reloaded on SIGHUP: swapped in whole once all of it loads, or not at all."""

import logging
import os
import signal
import threading
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from sql_warden import cli as cli_module
from sql_warden.audit import MemoryAuditSink
from sql_warden.auth import key_hash, new_api_key
from sql_warden.cli import DRIFTED, ONLY_READERS, cli
from sql_warden.engines import Column, Result, RoleReport, Table
from sql_warden.metrics import Metrics
from sql_warden.profiles import Access, Columns
from sql_warden.reload import Reloader, ReloadError
from sql_warden.server import LivePolicy, Policy
from sql_warden.startup import check_role, missing_from, unmasked
from sql_warden.warden import Warden
from tests.support import serving
from tests.unit.conftest import PRODUCTS, AuditSinks, FakeEngine
from tests.unit.test_http_auth import _client, _post, _structured

CUSTOMERS = Table(
    "public",
    "customers",
    (Column("id", "integer"), Column("email", "text"), Column("ssn", "text")),
)
CATALOG = (PRODUCTS, CUSTOMERS)
SUPERUSER = RoleReport("warden_reader", ("is a superuser",))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _access(rules: dict[str, Columns]) -> Access:
    return Access({(name.split(".")[0], name.split(".")[1]): cols for name, cols in rules.items()})


class TestWhatTheCatalogLacks:
    def test_a_table_that_is_gone(self) -> None:
        access = _access({"public.products": "*", "public.orders": frozenset({"id"})})
        assert missing_from(CATALOG, access) == ("table public.orders",)

    def test_columns_that_are_gone(self) -> None:
        access = _access(
            {
                "public.products": frozenset({"id", "price_cents"}),
                "public.customers": frozenset({"id", "phone", "fax"}),
            }
        )
        assert missing_from(CATALOG, access) == (
            "column price_cents of public.products",
            "columns fax, phone of public.customers",
        )

    def test_every_column_of_a_table_is_whatever_it_has(self) -> None:
        assert missing_from(CATALOG, _access({"public.customers": "*"})) == ()

    def test_a_profile_of_everything_or_none_names_nothing(self) -> None:
        assert missing_from(CATALOG, Access("*")) == ()
        assert missing_from(CATALOG, None) == ()

    def test_names_are_compared_as_stored(self) -> None:
        access = _access({"public.Products": "*", "PUBLIC.customers": "*"})
        assert missing_from(CATALOG, access) == (
            "table public.Products",
            "table PUBLIC.customers",
        )

    def test_masks_on_columns_and_tables_that_are_gone(self) -> None:
        masks = [
            ("public", "customers", "ssn"),
            ("public", "customers", "social_security_number"),
            ("public", "people", "ssn"),
        ]
        assert unmasked(CATALOG, masks) == (
            "public.customers.social_security_number",
            "public.people.ssn",
        )
        assert unmasked(CATALOG, [("public", "customers", "ssn")]) == ()

    def test_check_role_compares_the_profile_with_what_the_role_sees(self) -> None:
        engine = FakeEngine(catalog=(PRODUCTS,))
        check = check_role(
            engine, _access({"public.customers": "*"}), [("public", "customers", "ssn")]
        )
        assert (check.missing, check.unmasked, check.drifted) == (
            ("table public.customers",),
            ("public.customers.ssn",),
            True,
        )
        assert not check_role(engine, _access({"public.products": "*"})).drifted

    def test_a_role_that_can_write_isnt_compared(self) -> None:
        engine = FakeEngine(catalog=(), report=SUPERUSER)
        assert not check_role(engine, _access({"public.customers": "*"})).drifted


DRIFTING = """
version: 1
warehouse:
  dsn: postgresql://warden_reader:hunter2@db.internal:5432/warehouse
default_profile: support
masking:
  key: 0123456789abcdef0123
profiles:
  support:
    tables:
      public.products: [id, name, price_cents]
      public.customers: "*"
      public.orders: [id]
    masks:
      public.customers.ssn: {strategy: redact}
      public.customers.tax_id: {strategy: hmac}
  admin:
    tables: "*"
"""


@pytest.fixture
def drifting(tmp_path: Path) -> str:
    path = tmp_path / "drifting.yaml"
    path.write_text(DRIFTING)
    return str(path)


def _catalog(monkeypatch: pytest.MonkeyPatch, catalog: tuple[Table, ...], **settings: Any) -> None:
    monkeypatch.setattr(
        cli_module,
        "PostgresEngine",
        lambda dsn, **_: FakeEngine(
            dsn, catalog=catalog, report=RoleReport("warden_reader"), **settings
        ),
    )


class TestDriftWhereItIsChecked:
    def test_validate_live_fails_on_it(
        self, drifting: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _catalog(monkeypatch, CATALOG)
        outcome = CliRunner().invoke(cli, ["config", "validate", drifting, "--live"])
        assert outcome.exit_code == 1
        assert outcome.output.splitlines()[-8:] == [
            "  live:      support: role warden_reader can only read",
            "               ✗ the profile allows what the role can't see:",
            "                 column price_cents of public.products",
            "                 table public.orders",
            "               ✗ the profile masks columns the role can't see:",
            "                 public.customers.tax_id",
            "             admin: role warden_reader can only read",
            f"Error: {DRIFTED}",
        ]
        assert "hunter2" not in outcome.output

    def test_and_on_a_role_that_can_write_says_both(
        self, drifting: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def engine(dsn: str, **_: Any) -> FakeEngine:
            return FakeEngine(dsn, catalog=CATALOG, report=SUPERUSER)

        monkeypatch.setattr(cli_module, "PostgresEngine", engine)
        outcome = CliRunner().invoke(cli, ["config", "validate", drifting, "--live"])
        assert outcome.exit_code == 1
        # A role that can write isn't compared: it won't be served whatever it sees.
        assert outcome.output.splitlines()[-1] == (
            f"Error: a server would not start for every profile. {ONLY_READERS}"
        )

    def test_a_policy_that_matches_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "fits.yaml"
        path.write_text(
            "version: 1\nprofiles:\n  support:\n    tables:\n      public.products: [id, name]\n"
            "      public.customers: '*'\n    masks:\n      public.customers.ssn: "
            "{strategy: redact}\n"
        )
        _catalog(monkeypatch, CATALOG)
        outcome = CliRunner().invoke(cli, ["config", "validate", str(path), "--live"])
        assert outcome.exit_code == 0, outcome.output

    def test_a_server_starts_but_warns(
        self, drifting: str, monkeypatch: pytest.MonkeyPatch, audit_sinks: AuditSinks
    ) -> None:
        _catalog(monkeypatch, CATALOG)
        served: list[str] = []
        monkeypatch.setattr(
            cli_module,
            "create_server",
            lambda warden: type("S", (), {"run": lambda self, t: served.append(warden.profile)})(),
        )
        outcome = CliRunner().invoke(cli, ["--config", drifting, "serve"])
        assert outcome.exit_code == 0, outcome.output
        assert served == ["support"]
        assert outcome.stderr.splitlines() == [
            "warning: profile support allows what its role can't see, so queries for it are "
            "refused:",
            "  column price_cents of public.products",
            "  table public.orders",
            "Dropped or renamed in the warehouse, or never granted: fix the profile or the grants.",
            "warning: profile support masks columns its role can't see, so those masks protect "
            "nothing:",
            "  public.customers.tax_id",
            "If a column was renamed, it is not masked under its new name: mask that one.",
        ]


class Closing(FakeEngine):
    """An engine that says when it is closed, and can hold a query open."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.closed = 0
        self.hold: threading.Event | None = None
        self.running = threading.Event()

    def execute(self, sql: str, *, tag: str | None = None) -> Result:
        self.running.set()
        if self.hold is not None:
            assert self.hold.wait(10)
        return super().execute(sql, tag=tag)

    def close(self) -> None:
        self.closed += 1


def _warden(profile: str = "public", engine: FakeEngine | None = None) -> Warden:
    return Warden(engine or Closing(), audit=MemoryAuditSink(), profile=profile)


@dataclass
class Builds:
    """Stands in for the CLI's builder: hands out the policies it is given, in turn."""

    policies: list[Policy | Exception] = field(default_factory=list)
    calls: int = 0

    def __call__(self, current: Policy) -> Policy:
        self.calls += 1
        next_ = self.policies.pop(0)
        if isinstance(next_, Exception):
            raise next_
        return next_


class TestLivePolicy:
    def test_a_swap_answers_with_the_new_and_hands_back_the_old(self) -> None:
        old, new = Policy(_warden()), Policy(_warden())
        live = LivePolicy(old)
        assert live.swap(new) is old
        assert live.current is new

    def test_it_serves_the_way_it_did(self) -> None:
        live = LivePolicy(Policy(_warden()))
        with pytest.raises(ValueError, match="between one profile and every profile"):
            live.swap(Policy({"public": _warden()}))
        with pytest.raises(ValueError, match="authentication on or off"):
            live.swap(Policy(_warden(), authenticator=object()))  # type: ignore[arg-type]

    def test_a_policy_of_no_profiles_is_refused(self) -> None:
        with pytest.raises(ValueError, match="at least one profile"):
            Policy({})

    def test_its_profiles_cant_be_changed_behind_its_back(self) -> None:
        wardens = {"public": _warden()}
        policy = Policy(wardens)
        wardens["admin"] = _warden("admin")
        assert [w.profile for w in policy.all] == ["public"]


class TestReloader:
    def test_a_policy_that_builds_is_served(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.INFO, logger="sql_warden.reload")
        live = LivePolicy(Policy({"public": _warden()}, authenticator=object()))  # type: ignore[arg-type]
        new = Policy({"public": _warden(), "admin": _warden("admin")}, authenticator=object())  # type: ignore[arg-type]
        metrics = Metrics()
        reloader = Reloader(live, Builds([new]), source="warden.yaml", metrics=metrics, settle_s=0)
        assert reloader.reload()
        assert live.current is new
        assert caplog.messages == ["reloaded warden.yaml: serving profiles public, admin"]
        assert metrics.reloads.value(outcome="applied") == 1
        assert metrics.last_reload_ok.value == 1

    def test_one_that_doesnt_changes_nothing(self, caplog: pytest.LogCaptureFixture) -> None:
        old = Policy(_warden())
        live = LivePolicy(old)
        metrics = Metrics()
        builds = Builds(
            [ReloadError("warden.yaml: invalid YAML (line 3, col 1): oops"), Policy(_warden())]
        )
        reloader = Reloader(live, builds, source="warden.yaml", metrics=metrics, settle_s=0)
        assert not reloader.reload()
        assert live.current is old
        assert caplog.messages == [
            "could not reload warden.yaml, so the policy loaded before is still served: "
            "warden.yaml: invalid YAML (line 3, col 1): oops"
        ]
        assert caplog.records[0].levelno == logging.ERROR
        assert (metrics.reloads.value(outcome="failed"), metrics.last_reload_ok.value) == (1, 0)
        # Fixed and reloaded, it is served again.
        assert reloader.reload()
        assert metrics.last_reload_ok.value == 1

    def test_a_bug_is_named_but_its_message_kept_out_of_the_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        live = LivePolicy(Policy(_warden()))
        builds = Builds([RuntimeError("postgresql://warden:hunter2@db/warehouse")])
        assert not Reloader(live, builds).reload()
        assert caplog.messages[0].endswith(": unexpected RuntimeError")
        assert "hunter2" not in caplog.text

    def test_a_policy_that_serves_another_way_is_refused_and_closed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        engine = Closing()
        live = LivePolicy(Policy(_warden()))
        new = Policy({"public": _warden(engine=engine)}, authenticator=object())  # type: ignore[arg-type]
        assert not Reloader(live, Builds([new])).reload()
        assert "can't turn authentication on or off" in caplog.text
        assert engine.closed == 1

    def test_the_replaced_wardens_are_closed_once_their_requests_finish(self) -> None:
        engine = Closing()
        engine.hold = threading.Event()
        old = _warden(engine=engine)
        live = LivePolicy(Policy(old))
        reloader = Reloader(live, Builds([Policy(_warden())]), settle_s=0)
        running = threading.Thread(target=old.run, args=("select 1",))
        running.start()
        assert engine.running.wait(5)
        assert reloader.reload()
        assert not old.idle
        threading.Event().wait(0.3)
        assert engine.closed == 0  # still answering the request it had
        engine.hold.set()
        running.join(5)
        reloader.wait()
        assert (old.idle, engine.closed) == (True, 1)

    def test_signals_while_it_reloads_make_one_more_reload(self) -> None:
        started, release = threading.Event(), threading.Event()
        calls = []

        def build(current: Policy) -> Policy:
            calls.append(1)
            started.set()
            assert release.wait(5)
            return Policy(_warden())

        reloader = Reloader(LivePolicy(Policy(_warden())), build, settle_s=0)
        reloader.request()
        assert started.wait(5)
        for _ in range(3):
            reloader.request()
        release.set()
        reloader.wait()
        assert len(calls) == 2

    def test_sighup_reloads_while_installed(self) -> None:
        live = LivePolicy(Policy(_warden()))
        new = Policy(_warden())
        reloader = Reloader(live, Builds([new]), settle_s=0)
        before = signal.getsignal(signal.SIGHUP)
        with reloader.on_sighup() as installed:
            assert installed
            os.kill(os.getpid(), signal.SIGHUP)
            for _ in range(200):  # the handler runs in the main thread, between bytecodes
                if live.current is new:
                    break
                threading.Event().wait(0.01)
            reloader.wait()
        assert live.current is new
        assert signal.getsignal(signal.SIGHUP) is before

    def test_not_outside_the_main_thread(self) -> None:
        reloader = Reloader(LivePolicy(Policy(_warden())), Builds())
        got = []

        def elsewhere() -> None:
            with reloader.on_sighup() as installed:
                got.append(installed)

        thread = threading.Thread(target=elsewhere)
        thread.start()
        thread.join()
        assert got == [False]


KEY, NEW_KEY = new_api_key(), new_api_key()


def _served_policy(
    *,
    keys: str = f"    - {{name: web-agent, profile: public, sha256: {key_hash(KEY)}}}\n",
    public: str = "      public.products: [id]\n",
    audit: str = "",
    port: int = 8000,
    extra: str = "",
) -> str:
    return (
        "version: 1\n"
        "warehouse:\n  dsn: postgresql://warden_reader:hunter2@db.internal/warehouse\n"
        f"{audit}"
        f"server:\n  port: {port}\n"
        "profiles:\n"
        f"  public:\n    tables:\n{public}"
        "  admin:\n    tables: '*'\n"
        f"{extra}"
        f"auth:\n  api_keys:\n{keys}"
    )


@dataclass
class Serve:
    """`sql-warden serve --transport http`, up to where it would listen: the app it built
    and its Reloader, and the engines it made."""

    path: Path
    roles: dict[str, RoleReport] = field(default_factory=dict)
    built: list[str] = field(default_factory=list)
    app: Any = None
    reloader: Reloader | None = None
    stderr: str = ""

    def start(self, monkeypatch: pytest.MonkeyPatch, *args: str) -> None:
        def engine(dsn: str, *, max_rows: int, **_: Any) -> FakeEngine:
            user = dsn.split("//")[1].split(":")[0].split("@")[0]
            self.built.append(dsn)
            report = self.roles.get(user, RoleReport(user))
            return FakeEngine(dsn, max_rows=max_rows, catalog=CATALOG, report=report)

        def listen(
            app: Any, host: str, port: int, serving: str, grace_s: int, reloader: Reloader
        ) -> None:
            self.app, self.reloader = app, reloader

        monkeypatch.setattr(cli_module, "PostgresEngine", engine)
        monkeypatch.setattr(cli_module, "_listen", listen)
        outcome = CliRunner().invoke(
            cli, ["--config", str(self.path), "serve", "--transport", "http", *args]
        )
        assert outcome.exit_code == 0, outcome.output
        self.stderr = outcome.stderr

    def reload(self, text: str) -> bool:
        assert self.reloader is not None
        self.path.write_text(text)
        return self.reloader.reload()

    @property
    def live(self) -> LivePolicy:
        assert self.reloader is not None
        return self.reloader.live


@pytest.fixture
def serve(tmp_path: Path, audit_sinks: AuditSinks) -> Serve:
    path = tmp_path / "warden.yaml"
    path.write_text(_served_policy())
    return Serve(path)


async def _ask(url: str, token: str, sql: str) -> dict[str, Any]:
    async with _client(url, token) as client:
        return _structured(await client.call_tool("run_query", {"sql": sql}))


def _metric(base_url: str, name: str) -> str:
    with urllib.request.urlopen(f"{base_url}/metrics", timeout=10) as response:
        page: str = response.read().decode()
    return next(line for line in page.splitlines() if line.startswith(name))


@pytest.fixture
def http(serve: Serve, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    serve.start(monkeypatch)
    with serving(serve.app) as base_url:
        yield base_url


class TestServeReloads:
    @pytest.mark.anyio
    async def test_a_revoked_key_is_turned_away_and_a_new_one_let_in(
        self, serve: Serve, http: str
    ) -> None:
        url = f"{http}/mcp"
        assert (await _ask(url, KEY, "select id from products"))["profile"] == "public"
        assert _post(url, token=NEW_KEY)[0] == 401
        keys = f"    - {{name: ops, profile: admin, sha256: {key_hash(NEW_KEY)}}}\n"
        assert serve.reload(_served_policy(keys=keys))
        assert _post(url, token=KEY)[0] == 401
        answer = await _ask(url, NEW_KEY, "select name from products")
        assert (answer["profile"], answer["refused"]) == ("admin", False)

    @pytest.mark.anyio
    async def test_a_profile_s_rules_change(self, serve: Serve, http: str) -> None:
        url = f"{http}/mcp"
        assert (await _ask(url, KEY, "select name from products"))["code"] == "COLUMN_NOT_ALLOWED"
        assert serve.reload(_served_policy(public="      public.products: [id, name]\n"))
        assert (await _ask(url, KEY, "select name from products"))["refused"] is False

    @pytest.mark.anyio
    async def test_a_profile_is_added(self, serve: Serve, http: str) -> None:
        extra = "  support:\n    tables:\n      public.customers: [id]\n"
        keys = (
            f"    - {{name: web-agent, profile: public, sha256: {key_hash(KEY)}}}\n"
            f"    - {{name: helpdesk, profile: support, sha256: {key_hash(NEW_KEY)}}}\n"
        )
        assert serve.reload(_served_policy(extra=extra, keys=keys))
        answer = await _ask(f"{http}/mcp", NEW_KEY, "select id from customers")
        assert (answer["profile"], answer["refused"]) == ("support", False)
        assert {w.profile for w in serve.live.current.all} == {"public", "admin", "support"}

    @pytest.mark.anyio
    async def test_a_broken_file_keeps_the_policy_it_had(
        self, serve: Serve, http: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        before = serve.live.current
        assert not serve.reload("version: 1\nprofiles: [\n")
        assert serve.live.current is before
        assert f"could not reload {serve.path}" in caplog.text
        assert "invalid YAML" in caplog.text
        assert (await _ask(f"{http}/mcp", KEY, "select id from products"))["refused"] is False
        assert _metric(http, "sql_warden_config_last_reload_successful") == (
            "sql_warden_config_last_reload_successful 0"
        )
        assert _metric(http, 'sql_warden_config_reloads_total{outcome="failed"}').endswith(" 1")

    def test_so_does_a_role_that_can_now_write(
        self, serve: Serve, http: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        before = serve.live.current
        serve.roles["warden_reader"] = SUPERUSER
        assert not serve.reload(_served_policy(public="      public.products: [id, name]\n"))
        assert serve.live.current is before
        assert "profile public: role warden_reader can change the warehouse" in caplog.text
        assert "hunter2" not in caplog.text

    @pytest.mark.parametrize(
        ("change", "said"),
        [
            ({"audit": "audit:\n  dsn: postgresql://audit@elsewhere/audit\n"}, "audit changed"),
            ({"port": 9000}, "server changed"),
        ],
    )
    def test_what_only_a_restart_changes(
        self,
        serve: Serve,
        http: str,
        caplog: pytest.LogCaptureFixture,
        change: dict[str, Any],
        said: str,
    ) -> None:
        before = serve.live.current
        assert not serve.reload(_served_policy(**change))
        assert serve.live.current is before
        assert f"{said}, and only a restart changes it" in caplog.text

    def test_nor_turning_auth_off(
        self, serve: Serve, http: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        assert not serve.reload("version: 1\nserver:\n  port: 8000\n")
        assert "auth (added or removed) changed" in caplog.text


ONE_PROFILE = """
version: 1
warehouse:
  dsn: postgresql://warden_reader:hunter2@db.internal/warehouse
default_profile: {default}
profiles:
  public:
    tables:
      public.products: [{columns}]
  admin:
    tables: '*'
"""


class TestServeOneProfileReloads:
    @pytest.fixture
    def one(self, tmp_path: Path, audit_sinks: AuditSinks) -> Serve:
        path = tmp_path / "warden.yaml"
        path.write_text(ONE_PROFILE.format(default="public", columns="id"))
        return Serve(path)

    def test_it_keeps_serving_its_profile_and_session(
        self, one: Serve, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        one.start(monkeypatch)
        (before,) = one.live.current.all
        assert one.reload(ONE_PROFILE.format(default="admin", columns="id, name"))
        (after,) = one.live.current.all
        assert after is not before
        assert after.profile == "public"  # picked when it started, not the new default
        assert after.session_id == before.session_id
        assert after.run("select name from products").result is not None

    def test_not_once_its_profile_is_gone(
        self, one: Serve, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        one.start(monkeypatch)
        assert not one.reload("version: 1\nprofiles:\n  admin:\n    tables: '*'\n")
        assert "unknown profile 'public'" in caplog.text

    def test_the_command_line_still_wins(self, one: Serve, monkeypatch: pytest.MonkeyPatch) -> None:
        one.path.write_text("version: 1\n")
        one.start(monkeypatch, "--dsn", "postgresql://flagged:pw@db.internal/warehouse")
        assert one.reload("version: 1\nwarehouse:\n  max_rows: 7\n")
        assert [dsn.split("//")[1].split(":")[0] for dsn in one.built] == ["flagged", "flagged"]
        (warden,) = one.live.current.all
        assert warden.engine.max_rows == 7
