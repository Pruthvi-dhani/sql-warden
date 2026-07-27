"""The base model everything in sql-warden inherits from.

Two settings, both deliberate:

`frozen=True` -- nothing in this system should be mutable after construction. A limit that
can be raised at runtime is not a limit, and a decision that a later stage can edit in
place is not a decision.

`extra="forbid"` -- an unrecognised key is an error, never a shrug. Silently ignoring a
mistyped field means the control you believed you configured was never configured at all,
and the only symptom is the thing it was supposed to prevent.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
