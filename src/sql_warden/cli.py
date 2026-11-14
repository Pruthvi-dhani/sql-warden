import datetime
import json
import logging
import sys
import time
from collections.abc import Callable, Collection, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import click
import uvicorn
from mcp.server.mcpserver.exceptions import ToolError

from sql_warden import __version__
from sql_warden.audit import AuditError, AuditEvent, AuditReader, AuditSink, PostgresAuditSink
from sql_warden.auth import Authenticator, key_hash, new_api_key
from sql_warden.config import (
    EVERYTHING,
    IMPLICIT_PROFILE,
    ApiKeyConfig,
    AuthConfig,
    BudgetConfig,
    ConfigError,
    IdentityBudgetConfig,
    ProfileConfig,
    WardenConfig,
    default_config,
    describe_dsn,
    is_loopback,
    load_config,
)
from sql_warden.engines import Engine, EngineError
from sql_warden.engines.postgres import PostgresEngine
from sql_warden.engines.snowflake import BYTES, SnowflakeEngine
from sql_warden.metrics import Metrics
from sql_warden.pipeline.budget import window
from sql_warden.pipeline.cost import format_amount, format_cost
from sql_warden.profiles import (
    Profile,
    ProfileError,
    profile_budget,
    profile_cost,
    profile_identity_budget,
    select_profile,
)
from sql_warden.reload import Reloader, ReloadError
from sql_warden.render import (
    AUDIT_HEADER,
    audit_json,
    format_audit_event,
    format_audit_line,
    format_budget,
    format_decision,
    format_masked,
    format_rewrites,
    format_table,
    format_table_detail,
    format_tables,
)
from sql_warden.server import (
    LivePolicy,
    Policy,
    Readiness,
    create_http_app,
    create_server,
    describe,
    describe_one_table,
    describe_tables,
)
from sql_warden.sessions import Usage, valid_session_id
from sql_warden.startup import RoleCheck, check_role, listed
from sql_warden.warden import NOT_COUNTED, Warden

DEFAULT_CONFIG_PATH = Path("warden.yaml")
EXIT_ERROR = 1
EXIT_REFUSED = 2
"""A check refused the query. Nothing else exits 2, so scripts can tell a refusal apart."""
CLIENT = "cli"
"""How CLI requests are labelled in the audit log."""


@dataclass(frozen=True)
class CliState:
    config_path: Path | None


def resolve_config(path: Path | None) -> tuple[WardenConfig, str]:
    """The config to use and where it came from: --config, ./warden.yaml, or the defaults."""
    if path is None and DEFAULT_CONFIG_PATH.is_file():
        path = DEFAULT_CONFIG_PATH
    if path is None:
        return default_config(), "built-in defaults"
    try:
        return load_config(path), str(path)
    except ConfigError as exc:
        raise click.ClickException(str(exc)) from exc


def audit_dsn_option[F: Callable[..., Any]](command: F) -> F:
    return click.option(
        "--audit-dsn",
        envvar="SQL_WARDEN_AUDIT_DSN",
        help="Audit database connection string; overrides audit.dsn (env: SQL_WARDEN_AUDIT_DSN).",
    )(command)


def engine_options[F: Callable[..., Any]](command: F) -> F:
    command = audit_dsn_option(command)
    command = click.option(
        "--profile",
        envvar="SQL_WARDEN_PROFILE",
        help="Profile to serve, from warden.yaml's profiles (env: SQL_WARDEN_PROFILE). "
        "Default: default_profile.",
    )(command)
    command = click.option(
        "--timeout-ms",
        type=click.IntRange(min=1),
        help="Statement timeout; overrides warehouse.statement_timeout_ms.",
    )(command)
    command = click.option(
        "--max-rows", type=click.IntRange(min=1), help="Row cap; overrides warehouse.max_rows."
    )(command)
    command = click.option(
        "--dsn",
        envvar="SQL_WARDEN_DSN",
        help="Warehouse connection string, as in warden.yaml (snowflake://... for the "
        "snowflake engine); overrides warehouse.dsn, which profiles without their own dsn "
        "use (env: SQL_WARDEN_DSN).",
    )(command)
    return command


def settings(
    state: CliState,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    audit_dsn: str | None = None,
) -> WardenConfig:
    """The config file's settings with the command-line overrides applied."""
    config, _ = resolve_config(state.config_path)
    overrides = {"dsn": dsn, "max_rows": max_rows, "statement_timeout_ms": timeout_ms}
    warehouse = config.warehouse.model_copy(
        update={key: value for key, value in overrides.items() if value is not None}
    )
    audit = (
        config.audit if audit_dsn is None else config.audit.model_copy(update={"dsn": audit_dsn})
    )
    return config.model_copy(update={"warehouse": warehouse, "audit": audit})


def open_audit(config: WardenConfig) -> PostgresAuditSink:
    """The audit log, with its table set up. sql-warden doesn't start without one."""
    sink = PostgresAuditSink(config.audit.dsn, connect_timeout_s=config.audit.connect_timeout_s)
    try:
        sink.ensure_schema()
    except AuditError as exc:
        raise click.ClickException(
            f"audit database at {describe_dsn(config.audit.dsn)}: {exc}\n"
            "sql-warden records every request and won't run without its audit database."
        ) from exc
    return sink


def _session_name(ctx: click.Context, param: click.Parameter, value: str | None) -> str | None:
    if value is not None and not valid_session_id(value):
        raise click.BadParameter(
            "a session name is up to 64 letters, digits, '.', '_', ':' or '-', starting with "
            "a letter or digit"
        )
    return value


def session_option[F: Callable[..., Any]](command: F) -> F:
    return click.option(
        "--session",
        "session_id",
        callback=_session_name,
        help="The session this call belongs to, e.g. nightly-report: calls made with the "
        "same name are one session in the audit log. Default: a session of its own.",
    )(command)


def json_option[F: Callable[..., Any]](command: F) -> F:
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        help="Print the decision as one line of JSON: what the MCP tools return.",
    )(command)


def build_engine(config: WardenConfig, active: Profile) -> tuple[Engine, str | None]:
    """The engine a profile connects with, and the schema its unqualified table names are
    looked up in, where that isn't the dialect's usual one."""
    warehouse = config.warehouse
    # Like its dsn, a profile's own row cap is policy: --max-rows doesn't change it.
    max_rows = active.max_rows or warehouse.max_rows
    if warehouse.engine == "snowflake":
        try:
            snow = SnowflakeEngine(
                active.dsn,
                statement_timeout_ms=warehouse.statement_timeout_ms,
                max_rows=max_rows,
                connect_timeout_s=warehouse.connect_timeout_s,
            )
        except ValueError as exc:  # a dsn given on the command line: the file's was checked
            raise click.ClickException(f"warehouse dsn: {exc}") from exc
        # A table named without a schema is looked up in the session's, as Snowflake does.
        return snow, snow.default_schema
    postgres = PostgresEngine(
        active.dsn,
        statement_timeout_ms=warehouse.statement_timeout_ms,
        max_rows=max_rows,
        connect_timeout_s=warehouse.connect_timeout_s,
    )
    return postgres, None


def build_warden(
    config: WardenConfig,
    profile: str | None = None,
    *,
    audit: AuditSink | None = None,
    serving: bool = False,
    metrics: Metrics | None = None,
    session_id: str | None = None,
) -> Warden:
    """A Warden for one profile, recording to audit (by default, the configured audit database).

    A profile's own dsn wins over --dsn and SQL_WARDEN_DSN: it is part of the policy, often a
    role that can read less, and a flag must not widen it.

    serving is for a Warden that will answer agents: its database role is looked at first,
    and one that can write is refused (see vet_role). session_id is the Warden's own
    session, to carry one over from the Warden it replaces."""
    try:
        active = select_profile(config, profile)
    except ProfileError as exc:
        raise click.ClickException(str(exc)) from exc
    if audit is None:
        audit = open_audit(config)
    engine, default_schema = build_engine(config, active)
    # Budgets kept in the audit database, where every server recording there shares them,
    # so a session or caller gets no more by reaching another replica.
    sessions = None
    store_in = getattr(audit, "session_store", None)
    if callable(store_in) and (active.budget.limited or active.identity_budget.limited):
        sessions = store_in(active.name, not_counted=NOT_COUNTED)
    warden = Warden(
        engine,
        audit=audit,
        dialect=config.warehouse.dialect,
        default_schema=default_schema,
        shape=config.shape,
        profile=active.name,
        access=active.access,
        cost=active.cost,
        masks=active.masks,
        mask_key=None
        if config.masking.key is None
        else config.masking.key.get_secret_value().encode(),
        budget=active.budget,
        identity_budget=active.identity_budget,
        sessions=sessions,
        metrics=metrics,
        session_id=session_id,
    )
    if serving:
        try:
            vet_role(warden, active.dsn)
        except click.ClickException:
            warden.close()
            raise
    return warden


ONLY_READERS = (
    "sql-warden only serves as a role that can read and nothing more: then the database "
    "refuses a write even if every check here is wrong."
)


DRIFTED = (
    "the policy names tables or columns its roles can't see: dropped or renamed in the "
    "warehouse, or never granted. Fix the policy or the grants."
)


def vet_role(warden: Warden, dsn: str) -> RoleCheck:
    """Look at the database role a server is about to serve with. One that can write, or
    that can't be looked at, ends the command; one that can read more than its profile
    allows, or can't see what the profile names, gets a warning on stderr."""
    where = describe_dsn(dsn)
    try:
        check = check_role(warden.engine, warden.access, warden.masks)
    except EngineError as exc:
        raise click.ClickException(
            f"profile {warden.profile}: could not check what its role can do in the "
            f"warehouse ({where}): {exc}\n{ONLY_READERS}"
        ) from exc
    role = check.report.role
    if check.can_write:
        raise click.ClickException(
            "\n".join(
                [
                    f"profile {warden.profile}: role {role} can change the warehouse ({where}):",
                    *(f"  {line}" for line in listed(check.report.writes, prefix="it ")),
                    ONLY_READERS,
                ]
            )
        )
    if check.beyond:
        click.echo(
            "\n".join(
                [
                    f"warning: profile {warden.profile} allows less than its role can read. "
                    f"{role} can also read:",
                    *(f"  {line}" for line in listed(check.beyond)),
                    "Only the access check keeps the profile from these. Give the profile a "
                    "dsn of its own, for a role granted just what the profile allows.",
                ]
            ),
            err=True,
        )
    for line in drift_warnings(warden.profile, check):
        click.echo(line, err=True)
    return check


def drift_warnings(profile: str, check: RoleCheck) -> list[str]:
    """What a server says when its profile names what its role can't see. It still starts:
    a migration that drops a column shouldn't take it down, and such queries are refused."""
    lines = []
    if check.missing:
        lines += [
            f"warning: profile {profile} allows what its role can't see, so queries for it "
            "are refused:",
            *(f"  {line}" for line in listed(check.missing)),
            "Dropped or renamed in the warehouse, or never granted: fix the profile or the grants.",
        ]
    if check.unmasked:
        lines += [
            f"warning: profile {profile} masks columns its role can't see, so those masks "
            "protect nothing:",
            *(f"  {line}" for line in listed(check.unmasked)),
            "If a column was renamed, it is not masked under its new name: mask that one.",
        ]
    return lines


class _NotRecorded:
    """The audit sink for commands that run no queries. If one ever did, it would be refused:
    a query is never answered without a record."""

    def usage(self, session_id: str, profile: str, *, not_counted: Collection[str] = ()) -> Usage:
        raise AuditError("this command does not record queries")

    def ping(self) -> None:
        raise AuditError("this command does not record queries")

    def record(self, event: AuditEvent) -> None:
        self.ping()


NOT_RECORDED = _NotRecorded()


class UsageError(click.UsageError):
    exit_code = EXIT_ERROR


class Cli(click.Group):
    """Usage errors exit 1 like any other error; Click would use 2, which means refused here."""

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent: click.Context | None = None,
        **extra: Any,
    ) -> click.Context:
        try:
            return super().make_context(info_name, args, parent, **extra)
        except click.UsageError as exc:
            raise UsageError(exc.format_message(), exc.ctx) from exc

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except click.UsageError as exc:
            raise UsageError(exc.format_message(), exc.ctx) from exc


@click.group(cls=Cli)
@click.version_option(__version__, prog_name="sql-warden")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path, dir_okay=False),
    envvar="SQL_WARDEN_CONFIG",
    help="Policy file (env: SQL_WARDEN_CONFIG). Default: ./warden.yaml if present, "
    "otherwise settings for the local demo stack.",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Path | None) -> None:
    """A governed SQL gateway for AI agents."""
    # sqlglot warns when it falls back to an opaque Command (DO, EXPLAIN, ...). The shape
    # check refuses those with its own reason; the warning would only be noise.
    logging.getLogger("sqlglot").setLevel(logging.ERROR)
    ctx.obj = CliState(config_path)


@cli.command()
@click.argument("sql")
@engine_options
@session_option
@json_option
@click.pass_obj
def check(
    state: CliState,
    sql: str,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    session_id: str | None,
    as_json: bool,
) -> None:
    """Dry run: show what each check decides about SQL, without executing it.

    Exits 0 if the query would be allowed, 2 if a check refuses it, 1 on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms, audit_dsn), profile)
    decision = warden.check(sql, client=CLIENT, session_id=session_id)
    if as_json:
        click.echo(describe(decision).model_dump_json(exclude_none=True))
    else:
        click.echo(format_decision(decision, dry_run=True))
    if not decision.allowed:
        raise SystemExit(EXIT_REFUSED)


@cli.command()
@click.argument("sql")
@engine_options
@session_option
@json_option
@click.pass_obj
def query(
    state: CliState,
    sql: str,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    session_id: str | None,
    as_json: bool,
) -> None:
    """Run SQL through the checks and, if allowed, against the warehouse.

    Exits 0 if it ran, 2 if a check refused it, 1 if the database failed or on any other error.
    """
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms, audit_dsn), profile)
    outcome = warden.run(sql, client=CLIENT, session_id=session_id)
    if as_json:
        click.echo(describe(outcome.decision, outcome).model_dump_json(exclude_none=True))
    if outcome.error is not None:
        if as_json:
            raise SystemExit(EXIT_ERROR)
        raise click.ClickException(str(outcome.error)) from outcome.error
    if outcome.result is None:
        if not as_json:
            click.echo(format_decision(outcome.decision, dry_run=False))
        raise SystemExit(EXIT_REFUSED)
    if not as_json:
        click.echo(format_table(outcome.result, profile=warden.profile))
        decision = outcome.decision
        for note in [
            *format_masked(decision),
            *format_rewrites(decision),
            *format_budget(decision),
        ]:
            click.echo(note)


@cli.command("tables")
@click.argument("name", required=False)
@engine_options
@json_option
@click.pass_obj
def tables_command(
    state: CliState,
    name: str | None,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
    as_json: bool,
) -> None:
    """List the tables the profile may query, or describe one: `tables products`."""
    # Listing tables runs no query and isn't recorded, so it doesn't need the audit database.
    warden = build_warden(settings(state, dsn, max_rows, timeout_ms), profile, audit=NOT_RECORDED)
    try:
        if name is None:
            listed = describe_tables(warden)
            click.echo(listed.model_dump_json(by_alias=True) if as_json else format_tables(listed))
        else:
            one = describe_one_table(warden, name)
            click.echo(one.model_dump_json(by_alias=True) if as_json else format_table_detail(one))
    except ToolError as exc:
        raise click.ClickException(str(exc)) from exc


@cli.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "http"]),
    default="stdio",
    show_default=True,
    help="stdio for an agent that launches sql-warden; http for local tools like the portal.",
)
@click.option(
    "--host", help="HTTP only: the address to listen on; overrides server.host. Loopback only."
)
@click.option(
    "--port", type=click.IntRange(1, 65535), help="HTTP only; overrides server.port (8000)."
)
@engine_options
@click.pass_obj
def serve(
    state: CliState,
    transport: str,
    host: str | None,
    port: int | None,
    dsn: str | None,
    max_rows: int | None,
    timeout_ms: int | None,
    profile: str | None,
    audit_dsn: str | None,
) -> None:
    """Serve the MCP tools, recording every query in the audit database.

    Over stdio, and over HTTP without an auth section, it serves one profile. Over HTTP with
    an auth section it serves them all: each request's token says which it gets.

    It first asks the warehouse what each profile's role can do, and doesn't start as one
    that can write. `sql-warden config validate --live` checks every profile's role that way.

    Over HTTP, SIGHUP reloads the policy file: the new policy is served only once all of
    it loads and every role in it passes the same look; otherwise the old one still is.
    """
    config = settings(state, dsn, max_rows, timeout_ms, audit_dsn)
    if transport == "stdio":
        create_server(build_warden(config, profile, serving=True)).run("stdio")
        return
    if config.auth is not None and profile is not None:
        raise click.ClickException(
            "with an auth section, each request's token says which profile it gets: "
            "--profile is for stdio, where whoever starts the server picks"
        )
    audit = open_audit(config)  # one audit log for every profile, and for every reload
    metrics = Metrics()
    live = LivePolicy(_policy(config, profile, audit=audit, metrics=metrics))
    host, port = host or config.server.host, port or config.server.port
    try:
        app = create_http_app(
            live,
            host=host,
            allowed_hosts=config.server.allowed_hosts,
            allowed_origins=config.server.allowed_origins,
            metrics=metrics,
            readiness=readiness(live),
            max_concurrent_requests=config.server.max_concurrent_requests,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    if config.auth is not None and not is_loopback(host):
        click.echo(
            f"warning: serving plain HTTP on {host}. Every request carries its token, so put "
            "a proxy that terminates TLS in front of it, and let clients reach it only "
            "through the proxy.",
            err=True,
        )

    def reread() -> WardenConfig:
        return settings(state, dsn, max_rows, timeout_ms, audit_dsn)

    reloader = Reloader(
        live,
        policy_builder(reread, config, audit=audit, metrics=metrics),
        source=config_source(state),
        metrics=metrics,
    )
    if config.auth is None:
        serving = f"profile {live.current.all[0].profile}"
    else:
        serving = f"profiles {', '.join(config.profiles or {})}, to callers with a token"
    _listen(app, host, port, serving, config.server.shutdown_grace_s, reloader)


def _policy(
    config: WardenConfig,
    profile: str | None,
    *,
    audit: AuditSink,
    metrics: Metrics,
    replacing: Policy | None = None,
) -> Policy:
    """What an HTTP server serves under config: with an auth section every profile, each
    to callers whose token gives it; without, one profile. Every profile served has had
    its role looked at. replacing is the policy a reload replaces: its Wardens' own
    sessions carry over, and a server of one profile keeps serving that profile."""
    old = {} if replacing is None else {w.profile: w for w in replacing.all}

    def built(name: str | None) -> Warden:
        before = old.get(name or "")
        return build_warden(
            config,
            name,
            audit=audit,
            serving=True,
            metrics=metrics,
            session_id=None if before is None else before.session_id,
        )

    if config.auth is None:
        return Policy(built(profile))
    profiles = list(config.profiles or {})
    wardens: dict[str, Warden] = {}
    try:
        # Every profile is served, so every profile's role must be one that can't write.
        for name in profiles:
            wardens[name] = built(name)
        return Policy(wardens, Authenticator(config.auth, profiles))
    except BaseException:
        for warden in wardens.values():  # nothing will serve them
            warden.close()
        raise


RESTART_ONLY = ("audit", "server")
"""Sections a reload can't change: the audit log and the listening socket are opened once."""


def policy_builder(
    reread: Callable[[], WardenConfig],
    started: WardenConfig,
    *,
    audit: AuditSink,
    metrics: Metrics,
) -> Callable[[Policy], Policy]:
    """How a server's Reloader builds the policy afresh: reread() is the config as it is
    now, command-line overrides included; started is the one the server started with."""

    def build(current: Policy) -> Policy:
        try:
            config = reread()
            changed = [
                name for name in RESTART_ONLY if getattr(config, name) != getattr(started, name)
            ]
            if (config.auth is None) != (started.auth is None):
                changed.append("auth (added or removed)")
            if changed:
                it = "it" if len(changed) == 1 else "them"
                raise ReloadError(
                    f"{' and '.join(changed)} changed, and only a restart changes {it}"
                )
            # A server of one profile serves the one it started with, whatever the
            # default is now: it was picked when it started.
            profile = None if current.authenticator else current.all[0].profile
            return _policy(config, profile, audit=audit, metrics=metrics, replacing=current)
        except click.ClickException as exc:  # what a failed start would have said
            raise ReloadError(exc.format_message()) from exc

    return build


def config_source(state: CliState) -> str:
    """Where the policy comes from, as resolve_config finds it."""
    if state.config_path is not None:
        return str(state.config_path)
    return str(DEFAULT_CONFIG_PATH) if DEFAULT_CONFIG_PATH.is_file() else "the built-in defaults"


def readiness(live: LivePolicy) -> Readiness:
    """What /readyz checks: the audit database answers, and every profile's warehouse
    answers as a role that still can't write. Grants can change while a server runs, and
    a reload changes the profiles: the checks are those of the policy served now."""

    def checks() -> dict[str, Callable[[], None]]:
        wardens = live.current.all
        found: dict[str, Callable[[], None]] = {"audit": wardens[0].audit.ping}
        for warden in wardens:

            def read_only(engine: Engine = warden.engine) -> None:
                report = engine.role()
                if not report.read_only:
                    raise RuntimeError(f"role {report.role} can now change the warehouse")

            found[f"warehouse:{warden.profile}"] = read_only
        return found

    return Readiness(checks)


@contextmanager
def _log_to_stderr() -> Iterator[None]:
    """What sql-warden logs (reloads, readiness) goes to stderr, a line each."""
    logger = logging.getLogger("sql_warden")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


def _listen(app: Any, host: str, port: int, serving: str, grace_s: int, reloader: Reloader) -> None:
    url_host = f"[{host}]" if ":" in host else host
    with _log_to_stderr(), reloader.on_sighup() as reloads:
        click.echo(
            f"sql-warden MCP server on http://{url_host}:{port}/mcp, {serving} (Ctrl+C stops "
            f"it{', SIGHUP reloads the policy' if reloads else ''})",
            err=True,
        )
        # No Server header: what it runs on is nobody's business who can reach the port. On
        # SIGTERM uvicorn stops taking connections and lets the ones it has finish, for
        # grace_s.
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level="warning",
            server_header=False,
            timeout_graceful_shutdown=grace_s,
        )


FOLLOW_INTERVAL_S = 1.0
FOLLOW_LOOKBACK = datetime.timedelta(seconds=10)
"""How far back each --follow poll looks. An event's time is set when its request finishes, so
one can be written after a later one; looking back (and skipping ids already printed) catches
it."""


def _sleep(seconds: float) -> None:
    time.sleep(seconds)  # a function of its own, so tests can stand in for the wait


def _open_reader(state: CliState, audit_dsn: str | None) -> tuple[AuditReader, str]:
    config = settings(state, None, None, None, audit_dsn)
    reader = AuditReader(config.audit.dsn, connect_timeout_s=config.audit.connect_timeout_s)
    return reader, describe_dsn(config.audit.dsn)


@cli.group("audit")
def audit_group() -> None:
    """Read the audit log: every query and check sql-warden has answered."""


@audit_group.command()
@click.option(
    "-n", "--lines", "limit", type=click.IntRange(1, 10_000), default=20, show_default=True
)
@click.option("--profile", help="Only events for this profile.")
@click.option(
    "--session",
    "session_id",
    help="Only events of this session: a response's session_id, or a --session name.",
)
@click.option(
    "--identity",
    help="Only events of this caller: an API key's name, or oidc:<subject>.",
)
@click.option(
    "--decision",
    type=click.Choice(["allowed", "refused", "failed"]),
    help="Only events with this outcome.",
)
@click.option(
    "-f", "--follow", is_flag=True, help="Keep printing events as they are recorded (Ctrl+C stops)."
)
@click.option("--json", "as_json", is_flag=True, help="One JSON object per event, one per line.")
@audit_dsn_option
@click.pass_obj
def tail(
    state: CliState,
    limit: int,
    profile: str | None,
    session_id: str | None,
    identity: str | None,
    decision: Any,
    follow: bool,
    as_json: bool,
    audit_dsn: str | None,
) -> None:
    """The most recent events, oldest first. `audit show ID` has the details of one."""
    reader, where = _open_reader(state, audit_dsn)

    def emit(event: AuditEvent) -> None:
        click.echo(json.dumps(audit_json(event)) if as_json else format_audit_line(event))

    try:
        filters = {
            "profile": profile,
            "decision": decision,
            "session_id": session_id,
            "identity": identity,
        }
        events = reader.recent(limit, **filters)
        if not as_json:
            if events or follow:
                click.echo(AUDIT_HEADER)
            else:
                click.echo("(no audit events)")
        for event in events:
            emit(event)
        if not follow:
            return
        # Everything already in the window counts as printed: only new events follow.
        start = max([e.ts for e in events] + [datetime.datetime.now(datetime.UTC)])
        everything = {**filters, "decision": None}
        seen = {e.id: e.ts for e in reader.since(start - FOLLOW_LOOKBACK, **everything)}
        seen.update({e.id: e.ts for e in events})
        newest = start
        while True:
            _sleep(FOLLOW_INTERVAL_S)
            for event in reader.since(newest - FOLLOW_LOOKBACK, **filters):
                if event.id not in seen:
                    emit(event)
                    seen[event.id] = event.ts
                    newest = max(newest, event.ts)
            seen = {id_: ts for id_, ts in seen.items() if ts >= newest - FOLLOW_LOOKBACK}
    except AuditError as exc:
        raise click.ClickException(f"audit database at {where}: {exc}") from exc
    except KeyboardInterrupt:
        pass  # Ctrl+C is how --follow ends
    finally:
        reader.close()


@audit_group.command()
@click.argument("event_id")
@click.option("--json", "as_json", is_flag=True, help="Print the event as one line of JSON.")
@audit_dsn_option
@click.pass_obj
def show(state: CliState, event_id: str, as_json: bool, audit_dsn: str | None) -> None:
    """Everything recorded about one request: EVENT_ID is its audit_id, or the start of it."""
    reader, where = _open_reader(state, audit_dsn)
    try:
        matches = reader.find(event_id)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc
    except AuditError as exc:
        raise click.ClickException(f"audit database at {where}: {exc}") from exc
    finally:
        reader.close()
    if not matches:
        raise click.ClickException(f"no audit event {event_id}")
    if len(matches) > 1:
        raise click.ClickException(
            f"more than one audit event id starts with {event_id}; give more of it"
        )
    (event,) = matches
    click.echo(json.dumps(audit_json(event)) if as_json else format_audit_event(event))


@cli.group("auth")
def auth_group() -> None:
    """Make API keys for callers of the HTTP server."""


@auth_group.command("new-key")
@click.argument("name")
@click.option("--profile", "profile", required=True, help="The profile the key's holder gets.")
@click.pass_obj
def new_key(state: CliState, name: str, profile: str) -> None:
    """Make an API key for NAME (who will hold it, e.g. support-bot), and print the entry to
    add to auth.api_keys. Only the hash goes in the config: the key is shown this once."""
    config, source = resolve_config(state.config_path)
    if config.profiles is None:
        raise click.ClickException(
            f"{source} defines no profiles: a key gives its holder one, so define them first"
        )
    if profile not in config.profiles:
        raise click.ClickException(
            f"unknown profile '{profile}': {source} defines {', '.join(config.profiles)}"
        )
    taken = {key.name for key in config.auth.api_keys} if config.auth else set()
    if name in taken:
        raise click.ClickException(f"{source} already has a key named {name}")
    key = new_api_key()
    try:
        entry = ApiKeyConfig(name=name, profile=profile, sha256=key_hash(key))
    except ValueError as exc:
        raise click.ClickException(f"key name {name!r}: {_first_problem(exc)}") from exc
    click.echo(f"key: {key}")
    click.echo("")
    click.echo(f"Give it to {name}: it is shown only this once, and can't be recovered.")
    click.echo("They send it as `Authorization: Bearer <key>`. Add this under auth.api_keys:")
    click.echo("")
    click.echo(f"  - name: {entry.name}")
    click.echo(f"    profile: {entry.profile}")
    click.echo(f"    sha256: {entry.sha256}")


def _first_problem(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if callable(errors):
        found = errors()
        if found:
            return str(found[0]["msg"])
    return str(exc)


@cli.group()
def config() -> None:
    """Inspect the policy file."""


@config.command()
@click.argument("path", type=click.Path(path_type=Path, dir_okay=False), required=False)
@click.option(
    "--live",
    is_flag=True,
    help="Also connect to the warehouse as each profile's role: check that it can't write, "
    "what it can read beyond the profile, and that it can see every table, column and "
    "masked column the profile names.",
)
@click.pass_obj
def validate(state: CliState, path: Path | None, live: bool) -> None:
    """Check a policy file (default: --config, then ./warden.yaml) without connecting.

    With --live it then connects as each profile's role, as a server does before it starts,
    and exits 1 if any of them can write or can't be checked, or if a profile names a
    table, column or masked column its role can't see (dropped, renamed, or not granted).
    """
    path = path or state.config_path
    if path is None and not DEFAULT_CONFIG_PATH.is_file():
        raise click.ClickException(
            "no config file to validate: pass a path or --config, or create ./warden.yaml "
            "(start from warden.example.yaml)"
        )
    loaded, source = resolve_config(path)
    warehouse, shape = loaded.warehouse, loaded.shape
    click.echo(f"✓ {source} is valid")
    click.echo(f"  warehouse: {warehouse.engine} at {describe_dsn(warehouse.dsn)}")
    click.echo(
        f"             statement timeout {warehouse.statement_timeout_ms} ms, "
        f"max {warehouse.max_rows} rows"
    )
    click.echo(f"  audit:     postgres at {describe_dsn(loaded.audit.dsn)}")
    click.echo(
        f"  shape:     up to {shape.max_joins} joins, "
        f"subqueries up to {shape.max_subquery_depth} deep"
    )
    click.echo(
        "             LIMIT added or lowered to the row cap"
        if shape.limit == "inject"
        else "             LIMIT required, up to the row cap"
    )
    if shape.allowed_functions or shape.denied_functions:
        click.echo(
            f"             {len(shape.allowed_functions)} extra functions allowed, "
            f"{len(shape.denied_functions)} extra denied"
        )
    if shape.allowed_types:
        click.echo(f"             casts to {', '.join(shape.allowed_types)} allowed")
    unit = BYTES if warehouse.engine == "snowflake" else None
    scanned = " scanned" if unit else ""
    limit = format_amount(loaded.cost.max_total_cost, unit)
    click.echo(f"  cost:      refused above an estimated {limit}{scanned}")
    click.echo(f"  budgets:   {describe_budget(loaded.budgets)}")
    if loaded.identity_budgets.limited:
        click.echo(f"             {describe_identity_budget(loaded.identity_budgets)}")
    if "server" in loaded.model_fields_set:
        server = loaded.server
        host = f"[{server.host}]" if ":" in server.host else server.host
        reach = "this machine only" if server.local else f"as {', '.join(server.allowed_hosts)}"
        click.echo(f"  server:    http on {host}:{server.port}, {reach}")
        if server.allowed_origins:
            click.echo(f"             from pages at {', '.join(server.allowed_origins)}")
    for line in describe_auth(loaded.auth):
        click.echo(line)
    if loaded.masking.key is not None:
        click.echo("  masking:   hmac key set")
    for line in describe_profiles(loaded):
        click.echo(line)
    if live:
        lines, safe, drifted = describe_roles(loaded)
        for line in lines:
            click.echo(line)
        problems = [] if safe else [f"a server would not start for every profile. {ONLY_READERS}"]
        if drifted:
            problems.append(DRIFTED)
        if problems:
            raise click.ClickException("\n".join(problems))


def describe_roles(config: WardenConfig) -> tuple[list[str], bool, bool]:
    """What the warehouse says about each profile's role, for `config validate --live`:
    the lines to print, whether a server would start for every profile, and whether any
    profile names what its role can't see."""
    lines, safe, drifted = [], True, False
    for index, name in enumerate(config.profiles or [IMPLICIT_PROFILE]):
        label = "  live:      " if index == 0 else "             "
        active = select_profile(config, name)
        engine, _ = build_engine(config, active)
        try:
            check = check_role(engine, active.access, active.masks)
        except EngineError as exc:
            safe = False
            reason = str(exc).splitlines()[0]
            lines.append(f"{label}{name}: ✗ could not check its role: {reason}")
            continue
        finally:
            close = getattr(engine, "close", None)
            if close is not None:  # an engine that keeps a session open
                close()
        role = check.report.role
        if check.can_write:
            safe = False
            lines.append(f"{label}{name}: ✗ role {role} can change the warehouse")
            lines += [
                f"               {line}" for line in listed(check.report.writes, prefix="it ")
            ]
            continue
        lines.append(f"{label}{name}: role {role} can only read")
        if check.beyond:
            lines.append("               ! but more than the profile allows:")
            lines += [f"                 {line}" for line in listed(check.beyond)]
        if check.missing:
            lines.append("               ✗ the profile allows what the role can't see:")
            lines += [f"                 {line}" for line in listed(check.missing)]
        if check.unmasked:
            lines.append("               ✗ the profile masks columns the role can't see:")
            lines += [f"                 {line}" for line in listed(check.unmasked)]
        drifted = drifted or check.drifted
    return lines, safe, drifted


def describe_auth(auth: AuthConfig | None) -> list[str]:
    """Who may call over HTTP, for config validate: never a key or its hash."""
    if auth is None:
        return ["  auth:      none: HTTP needs no token, and is served on loopback only"]
    lines = []
    if auth.api_keys:
        keys = ", ".join(f"{key.name} → {key.profile}" for key in auth.api_keys)
        noun = "key" if len(auth.api_keys) == 1 else "keys"
        lines.append(f"{len(auth.api_keys)} API {noun}: {keys}")
    oidc = auth.oidc
    if oidc is not None:
        lines.append(f"oidc from {oidc.issuer}, for audience {oidc.audience}")
        if oidc.group_profiles:
            groups = ", ".join(f"{g} → {p}" for g, p in oidc.group_profiles.items())
            lines.append(f"  profile by group ({oidc.group_claim}): {groups}")
        else:
            lines.append(f"  profile from the {oidc.profile_claim} claim")
    return [
        ("  auth:      " if index == 0 else "             ") + line
        for index, line in enumerate(lines)
    ]


def describe_identity_budget(budget: IdentityBudgetConfig) -> str:
    """A caller's budget in a line: `per caller over any 24 hours: 500 queries`."""
    limits = describe_budget(budget).removeprefix("per session: ")
    return f"per caller over any {window(budget.window_hours)}: {limits}"


def describe_budget(budget: BudgetConfig) -> str:
    """A session budget in a line: `per session: 20 queries, cost 50,000`."""
    limits = [
        (budget.max_queries, "{} queries"),
        (budget.max_total_cost, "cost {}"),
        (budget.max_rows_returned, "{} rows"),
        (budget.max_refusals, "{} refusals"),
    ]
    set_ = [text.format(format_cost(limit)) for limit, text in limits if limit is not None]
    return "per session: " + ", ".join(set_) if set_ else "none: a session is not limited"


def describe_profile_tables(profile: ProfileConfig) -> list[str]:
    if profile.tables == EVERYTHING:
        return ["reads every table its role can"]
    assert isinstance(profile.tables, dict)
    if not profile.tables:
        return ["reads nothing: it lists no tables"]
    return [
        f"reads {name} ({'every column' if columns == EVERYTHING else ', '.join(columns)})"
        for name, columns in profile.tables.items()
    ]


def lower_case_names(profile: ProfileConfig) -> list[str]:
    """Names in a profile that Snowflake most likely stores otherwise: it keeps an unquoted
    name in upper case, and the profile must name tables and columns as they are stored."""
    names = [*profile.masks]
    if isinstance(profile.tables, dict):
        for table, columns in profile.tables.items():
            names.append(table)
            names += [] if columns == EVERYTHING else list(columns)
    lower = [name for name in names if name != name.upper()]
    return [
        f"{name} is not upper case: Snowflake stores a name as {name.upper()} unless it was "
        "created in quotes"
        for name in dict.fromkeys(lower)
    ]


def describe_profiles(config: WardenConfig) -> list[str]:
    if config.profiles is None:
        return [
            f"  profiles:  ! none defined: every server uses the implicit profile "
            f"'{IMPLICIT_PROFILE}',",
            "             which can read everything the warehouse role can",
        ]
    lines = []
    for index, (name, profile) in enumerate(config.profiles.items()):
        label = "  profiles:  " if index == 0 else "             "
        default = " (default)" if name == config.default_profile else ""
        where = (
            f"connects to {describe_dsn(profile.dsn)}"
            if profile.dsn is not None
            else "connects with warehouse.dsn"
        )
        lines.append(f"{label}{name}{default}: {where}")
        lines += [f"               {line}" for line in describe_profile_tables(profile)]
        if config.warehouse.engine == "snowflake":
            lines += [f"               ! {line}" for line in lower_case_names(profile)]
        if profile.max_rows is not None:
            lines.append(f"               max {profile.max_rows} rows")
        for name, rule in profile.masks.items():
            opened = ", may be filtered and joined on" if rule.allow_in_predicates else ""
            lines.append(f"               masks {name} ({rule.strategy}{opened})")
        if profile.cost is not None:
            unit = BYTES if config.warehouse.engine == "snowflake" else None
            limit = format_amount(profile_cost(config, profile).max_total_cost, unit)
            lines.append(
                f"               refused above an estimated {limit}{' scanned' if unit else ''}"
            )
        if profile.budgets is not None:
            budget = describe_budget(profile_budget(config, profile))
            lines.append(f"               budget {budget}")
        if profile.identity_budgets is not None:
            theirs = describe_identity_budget(profile_identity_budget(config, profile))
            lines.append(f"               budget {theirs}")
    if config.default_profile is None:
        lines.append("             no default_profile: servers must be given --profile")
    return lines
