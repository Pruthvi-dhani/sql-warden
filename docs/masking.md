# Masking

A profile can be allowed to read a column and still never see its real values. The column
comes back masked: redacted, partly starred, replaced by a token, or emptied. This page
covers how to set masks, what each strategy shows, and what a query may do with a masked
column.

## Setting masks

Masks are listed under a profile, keyed `schema.table.column`. They belong to the profile,
not the column, so `admin` can see in the clear what `support` sees masked:

```yaml
masking:
  key: ${WARDEN_MASK_KEY}      # for hmac; never in the file itself
profiles:
  support:
    tables:
      public.customers: "*"
    masks:
      public.customers.ssn: redact     # [REDACTED]
      public.customers.phone: partial  # ********0001: the last 4 kept
      public.customers.email: hmac     # 3f9a1c0b7e2d4a61: a keyed token
```

## The strategies

| Strategy  | Shows                                  | Settings                                        |
|-----------|----------------------------------------|-------------------------------------------------|
| `redact`  | `[REDACTED]`                           | `{strategy: redact, text: "***"}`               |
| `partial` | the ends, the rest starred: `********0001` | `keep_first`, `keep_last` (alone: the last 4). Never more than half a value |
| `hmac`    | a 16-hex-character token, the same for the same value, so results can still be matched and counted | needs `masking.key` (16+ bytes), shared by every profile |
| `null`    | nothing, not even whether there was a value | |

`NULL` stays `NULL` under the first three. A column made from more than one masked column (a
`UNION ALL` of two, say) comes back hidden whole.

Nothing is hidden about the masking itself: responses list `masked_columns`, the CLI prints
`masked: email (hmac)`, `list_tables` marks masked columns with `mask`, and the audit record
lists them too.

## What a query may do with a masked column

A masked column can be selected as it is, or counted, and nothing more. Filtering, joining,
grouping or sorting on it, or computing with it, could reveal what the mask hides, so the
[masking check](checks.md#masking) refuses those.

For a column that is hidden but not secret, `{strategy: hmac, allow_in_predicates: true}` lets
queries filter, join, group and sort on it; what is computed from it still comes back hidden.

## The hmac key

The `hmac` strategy needs a key, set once in the `masking` section and shared by every
profile. The key is a secret: whoever has it can check a guess against a token. sql-warden has no
built-in key and won't start if a profile uses `hmac` without one. The example config's
default after `:-` is for the local demo stack only.

## An example

The example policy's `support` profile may read all of `customers`, with three columns
masked:

```text
$ uv run sql-warden query "select id, phone, ssn, email from customers order by id limit 3" --profile support
id | phone       | ssn        | email
---+-------------+------------+-----------------
1  | *******7919 | [REDACTED] | d84c5e2dccdb9974
2  | *******5838 | [REDACTED] | f6ba72595cc1c3dc
3  | *******3757 | [REDACTED] | 2427ddca54b320ca
(3 rows, 19 ms, profile support)
masked: phone (partial)
masked: ssn (redact)
masked: email (hmac)
session budget: 0 of 50 refusals used
```

The same query as `admin` returns the real values.

## Where next

- [The masking check](checks.md#masking): each kind of query it refuses, with examples.
- [Profiles](policy.md#profiles): what a profile may read in the first place.
