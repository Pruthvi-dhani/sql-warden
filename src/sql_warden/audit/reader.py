"""Reading the audit log back: for `sql-warden audit tail` and `audit show`."""

import dataclasses
import datetime
import re
import uuid
from typing import Any, cast

import psycopg
from psycopg import errors, sql
from psycopg.rows import dict_row

from sql_warden.audit.sink import AuditError, AuditEvent, Decision

_FIELDS = tuple(field.name for field in dataclasses.fields(AuditEvent))
_SELECT = sql.SQL("SELECT {} FROM audit_events").format(
    sql.SQL(", ").join(sql.Identifier(name) for name in _FIELDS)
)
MIN_PREFIX = 4
"""The fewest characters of an id that `show` accepts, as git does for commit hashes."""
_ID_PREFIX = re.compile(r"[0-9a-f-]+")


class AuditReader:
    """Reads audit_events with one connection, kept open so `tail --follow` can poll."""

    def __init__(self, dsn: str, *, connect_timeout_s: int = 5) -> None:
        self._dsn = dsn
        self._connect_timeout_s = connect_timeout_s
        self._conn: psycopg.Connection[dict[str, Any]] | None = None

    def recent(
        self,
        limit: int,
        *,
        profile: str | None = None,
        decision: Decision | None = None,
        session_id: str | None = None,
    ) -> list[AuditEvent]:
        """The last limit events, oldest first, as tail prints them."""
        where, params = _filters(profile, decision, session_id)
        query = sql.SQL("{} {} ORDER BY ts DESC, id DESC LIMIT %s").format(_SELECT, where)
        return self._events(query, [*params, limit])[::-1]

    def since(
        self,
        ts: datetime.datetime,
        *,
        profile: str | None = None,
        decision: Decision | None = None,
        session_id: str | None = None,
    ) -> list[AuditEvent]:
        """Every event at or after ts, oldest first."""
        where, params = _filters(profile, decision, session_id, since=ts)
        query = sql.SQL("{} {} ORDER BY ts, id").format(_SELECT, where)
        return self._events(query, params)

    def find(self, id_or_prefix: str) -> list[AuditEvent]:
        """The event with this id, or every event whose id starts with it (at most two: enough
        to tell that a prefix is ambiguous)."""
        text = id_or_prefix.strip().lower()
        try:
            exact = uuid.UUID(text)
        except ValueError:
            exact = None
        if exact is not None:
            return self._events(sql.SQL("{} WHERE id = %s").format(_SELECT), [exact])
        if len(text) < MIN_PREFIX or not _ID_PREFIX.fullmatch(text):
            raise ValueError(
                f"'{id_or_prefix}' is not an audit id: give the id, or at least its first "
                f"{MIN_PREFIX} characters"
            )
        query = sql.SQL("{} WHERE id::text LIKE %s ORDER BY ts LIMIT 2").format(_SELECT)
        return self._events(query, [f"{text}%"])

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _events(self, query: sql.Composed, params: list[Any]) -> list[AuditEvent]:
        try:
            rows = self._connection().execute(query, params).fetchall()
        except errors.UndefinedTable:
            return []  # sql-warden has never started against this database: nothing recorded
        except psycopg.Error as exc:
            self.close()
            raise AuditError(f"could not read the audit log: {str(exc).strip()}") from exc
        return [_event(row) for row in rows]

    def _connection(self) -> psycopg.Connection[dict[str, Any]]:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg.connect(
                self._dsn,
                autocommit=True,
                connect_timeout=self._connect_timeout_s,
                row_factory=dict_row,
            )
        return self._conn


def _filters(
    profile: str | None,
    decision: Decision | None,
    session_id: str | None = None,
    *,
    since: datetime.datetime | None = None,
) -> tuple[sql.Composable, list[Any]]:
    conditions: list[sql.Composable] = []
    params: list[Any] = []
    filters = (
        ("profile", profile),
        ("decision", decision),
        ("session_id", session_id),
        ("ts", since),
    )
    for column, value in filters:
        if value is not None:
            op = ">=" if column == "ts" else "="
            conditions.append(sql.SQL("{} {} %s").format(sql.Identifier(column), sql.SQL(op)))
            params.append(value)
    if not conditions:
        return sql.SQL(""), params
    return sql.SQL("WHERE ") + sql.SQL(" AND ").join(conditions), params


def _event(row: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        **{
            **row,
            "decision": cast(Decision, row["decision"]),
            "rewrites": tuple(row["rewrites"]),
            "masked_columns": tuple(row["masked_columns"]),
            "trace": tuple(row["trace"]),
        }
    )
