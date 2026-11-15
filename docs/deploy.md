# Deploying sql-warden

How to run sql-warden as a central service: agents connect over HTTPS with a token, and only
sql-warden holds credentials for the databases behind it. This guide covers the databases'
roles, secrets, Kubernetes and ECS, the network, and keeping the audit log.

What it assumes: you have read about [profiles](policy.md#profiles),
[defence in depth](defence-in-depth.md), [authentication](mcp-server.md#authentication)
and [running it as a service](operations.md).

```
  agents ──HTTPS──▶ proxy (TLS) ──HTTP──▶ sql-warden ×N ──▶ warehouse (read replica, or Snowflake)
                                              │
                                              └───────────▶ audit database (Postgres, elsewhere)
```

- **The warehouse** is a Postgres read replica or Snowflake. sql-warden connects as roles
  that can only read, one per profile where profiles differ.
- **The audit database** is a Postgres of its own, ideally in another account than the
  warehouse, so nobody who can reach one can reach the other. sql-warden connects as a role
  that can add records and never change or remove one.
- **sql-warden** runs as N replicas behind the proxy. They share budgets through the audit
  database, so a caller gets no more by reaching another replica.
- **Only sql-warden** can reach either database. Agents reach only the proxy.

## 1. The warehouse's roles

Give each profile that should see less its own `dsn`, for a role granted just what the
profile allows. Then the database refuses what the access check would. A server refuses to
start as a role that can write, and warns when a role can read more than its profile:

```sql
CREATE ROLE warden_public LOGIN PASSWORD '...';
GRANT USAGE ON SCHEMA public TO warden_public;
GRANT SELECT (id, name, price_cents) ON public.products TO warden_public;
```

**Connections.** Each server keeps up to `warehouse.pool.max_size` (10) connections open for
each profile, so the replica's `max_connections` must allow replicas × profiles ×
`max_size`, beside whatever else uses it. Size it from `sql_warden_pool_requests_waiting`:
requests that wait often want a bigger pool, or more replicas. A connection is replaced
after `max_lifetime_s` (30 minutes), so a replica that failed over to a new address behind
the same name is reached without a restart. A rotated password is not: new connections still
use the one the process started with (see Secrets).

On Snowflake, give sql-warden a warehouse of its own (an XS one is plenty) with a resource
monitor, so no query, however it gets past the cost check, can spend more than you set (as
with all of sql-warden's Snowflake support, this has not been run against a real account):

```sql
CREATE WAREHOUSE sql_warden_wh WAREHOUSE_SIZE = XSMALL AUTO_SUSPEND = 60;
CREATE RESOURCE MONITOR sql_warden_monitor WITH CREDIT_QUOTA = 50 FREQUENCY = MONTHLY
    START_TIMESTAMP = IMMEDIATELY TRIGGERS ON 100 PERCENT DO SUSPEND_IMMEDIATE;
ALTER WAREHOUSE sql_warden_wh SET RESOURCE_MONITOR = sql_warden_monitor;
```

## 2. The audit database's roles

An audit log the server can rewrite records nothing an intruder in the server couldn't
erase. So the server's role may add records and read them back (budgets are read from
them), and nothing more. [`deploy/audit_roles.sql`](../deploy/audit_roles.sql) makes four
group roles:

| Role                | Who uses it           | What it may do                                                            |
|---------------------|-----------------------|---------------------------------------------------------------------------|
| `sql_warden_owner`  | upgrades              | owns the tables: the only role that may change them                       |
| `sql_warden_writer` | the server            | add records and read them; keep the budget tables. No UPDATE, DELETE or TRUNCATE on `audit_events` |
| `sql_warden_pruner` | the retention job     | remove old rows, reading only their times, and record each removal in `audit_prunes`, which it can add to and nothing more |
| `sql_warden_reader` | people, and exports   | read records                                                              |

Once, as the audit database's administrator:

```bash
psql "$AUDIT_ADMIN_DSN" -f deploy/audit_roles.sql
psql "$AUDIT_ADMIN_DSN" <<'SQL'
CREATE ROLE warden LOGIN PASSWORD '...' IN ROLE sql_warden_writer;
CREATE ROLE audit_retention LOGIN PASSWORD '...' IN ROLE sql_warden_pruner;
CREATE ROLE audit_analyst LOGIN PASSWORD '...' IN ROLE sql_warden_reader;
SQL
sql-warden audit init --owner sql_warden_owner --audit-dsn "$AUDIT_ADMIN_DSN"
```

`audit init` makes the tables as `sql_warden_owner` and grants each role what the table above
says. Run it again after every upgrade, before the new version starts: a server whose role
doesn't own the tables can't update them, and refuses to start until they are current,
saying so.

Then set `audit.append_only: true`. A server checks its audit role as it starts, and with it
refuses one that could change or remove records (as superuser, as the tables' owner or a
member of it, or with UPDATE, DELETE or TRUNCATE): a deploy with the wrong credentials stops
there instead of running unguarded. `sql-warden config validate --live` checks the same.

**An audit database from before this.** Its tables belong to whichever role first started a
server. Run `deploy/audit_roles.sql`, then hand the tables to the owner, then `audit init`:

```sql
ALTER TABLE audit_events OWNER TO sql_warden_owner;
ALTER TABLE session_usage OWNER TO sql_warden_owner;
ALTER TABLE caller_charges OWNER TO sql_warden_owner;
```

What this does not stop: a server's role can still **add** records, so an intruder in the
server could add false ones, and it can change the budget tables (a session's or a caller's
use), which are not the record. Nothing in the database can tell a forged record from a true
one; keeping the audit database out of the server's reach otherwise, and exporting it
elsewhere often, is what limits that.

### Retention

`sql-warden audit prune --older-than 90d`, run on a schedule as `audit_retention`, removes
the events recorded before the cutoff, the budgets of sessions idle since then, and callers'
charges older than any budget's window. Everything one prune removes, and the row in
`audit_prunes` saying who removed how much from before when, is one transaction. `--dry-run`
counts and removes nothing. It refuses to remove records less than a day old.

### Exporting for analytics

`sql-warden audit export --since T --until T` writes every event recorded in the window as
JSON Lines, oldest first, as `audit_analyst`. It only reads: nothing flows back. Windows that
meet export each event once, so a daily job can export yesterday:

```bash
sql-warden audit export --since 2026-11-13 --until 2026-11-14 -o audit-2026-11-13.jsonl
```

Into Snowflake, for example, through a stage (this has not been run against a real account):

```sql
CREATE TABLE sql_warden_audit (event VARIANT, loaded_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());
CREATE STAGE sql_warden_audit_stage FILE_FORMAT = (TYPE = JSON);
-- PUT file://audit-2026-11-13.jsonl @sql_warden_audit_stage;
COPY INTO sql_warden_audit (event) FROM @sql_warden_audit_stage;
CREATE VIEW sql_warden_audit_events AS SELECT
    event:id::string AS id, event:ts::timestamp_tz AS ts, event:profile::string AS profile,
    event:identity::string AS identity, event:decision::string AS decision,
    event:code::string AS code, event:sql::string AS sql
FROM sql_warden_audit;
```

## 3. Secrets

Every value in `warden.yaml` can be `${NAME}` or `${NAME:-default}`, read from the
environment when the file loads. Keep passwords and the masking key there, injected by the
platform from a secrets manager, and keep the file itself in git, changed through review.
What is safe in the file: API keys' **hashes** (`sql-warden auth new-key` prints the entry),
the OIDC issuer and audience, everything else.

```yaml
version: 1
warehouse:
  dsn: ${WAREHOUSE_DSN}
audit:
  dsn: ${AUDIT_DSN}
  append_only: true
masking:
  key: ${MASKING_KEY}
server:
  allowed_hosts: [sql-warden.example.com]
default_profile: support
profiles:
  public:
    dsn: ${WAREHOUSE_PUBLIC_DSN}
    tables:
      public.products: [id, name, price_cents]
  support:
    tables:
      public.customers: [id, email]
    masks:
      public.customers.email: {strategy: hmac}
auth:
  oidc:
    issuer: https://login.example.com/
    audience: sql-warden
    jwks_url: https://login.example.com/.well-known/jwks.json
    group_claim: groups
    group_profiles:
      data-support: support
      storefront: public
```

A process reads its environment once, when it starts, so a rotated password takes a restart
(a rolling one: replicas share everything else through the databases). A reload re-reads
the file, not the environment. A rotated masking key changes every hmac token, so masked
values no longer join with ones exported before.

## 4. Kubernetes

The policy in a ConfigMap, the secrets in a Secret (or synced from your secrets manager),
and the image as it is: it runs as uid 10001, needs no capabilities and writes nothing to
its filesystem.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: sql-warden
data:
  warden.yaml: |
    version: 1
    warehouse:
      dsn: ${WAREHOUSE_DSN}
    audit:
      dsn: ${AUDIT_DSN}
      append_only: true
    server:
      allowed_hosts: [sql-warden.example.com]
    profiles:
      public:
        tables:
          public.products: [id, name, price_cents]
    auth:
      api_keys:
        - {name: storefront-agent, profile: public, sha256: "<from sql-warden auth new-key>"}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sql-warden
spec:
  replicas: 2
  selector:
    matchLabels: {app: sql-warden}
  template:
    metadata:
      labels: {app: sql-warden}
    spec:
      terminationGracePeriodSeconds: 45  # above server.shutdown_grace_s (30)
      containers:
        - name: sql-warden
          image: registry.example.com/sql-warden:0.1.0
          ports: [{containerPort: 8000, name: http}]
          envFrom:
            - secretRef: {name: sql-warden}  # WAREHOUSE_DSN, AUDIT_DSN, ...
          volumeMounts:
            - {name: policy, mountPath: /etc/sql-warden, readOnly: true}
          livenessProbe:
            httpGet: {path: /healthz, port: http}
          readinessProbe:
            httpGet: {path: /readyz, port: http}
            periodSeconds: 10
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 250m, memory: 256Mi}
            limits: {memory: 512Mi}
      volumes:
        - name: policy
          configMap: {name: sql-warden}  # a directory: not subPath, which is never updated
---
apiVersion: v1
kind: Service
metadata:
  name: sql-warden
spec:
  selector: {app: sql-warden}
  ports: [{port: 80, targetPort: http}]
```

Route only `/mcp` from the proxy (an Ingress, or your gateway); `/healthz`, `/readyz` and
`/metrics` are for the cluster.

**Reloading the policy.** When the ConfigMap changes, the kubelet updates the mounted file
a minute or two later; then send each pod `SIGHUP`. The image has no shell, but has Python:

```bash
for pod in $(kubectl get pods -l app=sql-warden -o name); do
  kubectl exec "$pod" -- python -c "import os, signal; os.kill(1, signal.SIGHUP)"
done
```

A pod whose reload fails keeps its old policy and logs why;
`sql_warden_config_last_reload_successful` is then `0` for it, which is the thing to alert
on. `kubectl rollout restart deployment/sql-warden` is the alternative that always works.

**The network.** Only the proxy may reach sql-warden, and sql-warden may reach only DNS, the
two databases and the identity provider:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sql-warden
spec:
  podSelector:
    matchLabels: {app: sql-warden}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: ingress}
      ports: [{port: 8000}]
    - from:
        - namespaceSelector:
            matchLabels: {kubernetes.io/metadata.name: monitoring}
      ports: [{port: 8000}]
  egress:
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels: {k8s-app: kube-dns}
      ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
    - to:
        - ipBlock: {cidr: 10.20.0.10/32}  # the warehouse replica
        - ipBlock: {cidr: 10.30.0.10/32}  # the audit database
      ports: [{port: 5432}]
    - to:
        - ipBlock: {cidr: 0.0.0.0/0}  # the identity provider and Snowflake: narrow these
      ports: [{port: 443}]
```

And on the databases' side, the same from the other direction: the warehouse's and the audit
database's firewalls (security groups, `pg_hba.conf`) let in only sql-warden's addresses, and
the audit database's let in the retention job and the people who read it.

**Retention**, with the same image:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: sql-warden-audit-prune
spec:
  schedule: "17 3 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: prune
              image: registry.example.com/sql-warden:0.1.0
              args: [audit, prune, --older-than, 90d]
              env:
                - name: SQL_WARDEN_AUDIT_DSN
                  valueFrom:
                    secretKeyRef: {name: sql-warden-retention, key: dsn}
              securityContext:
                runAsNonRoot: true
                readOnlyRootFilesystem: true
                allowPrivilegeEscalation: false
                capabilities: {drop: [ALL]}
```

## 5. ECS

The same container on Fargate, with secrets from Secrets Manager, and the policy file from
the image built on top of this one, or from an EFS volume:

```json
{
  "family": "sql-warden",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::123456789012:role/sql-warden-execution",
  "containerDefinitions": [
    {
      "name": "sql-warden",
      "image": "123456789012.dkr.ecr.eu-west-1.amazonaws.com/sql-warden:0.1.0",
      "portMappings": [{"containerPort": 8000}],
      "readonlyRootFilesystem": true,
      "user": "10001",
      "linuxParameters": {"capabilities": {"drop": ["ALL"]}},
      "stopTimeout": 45,
      "secrets": [
        {"name": "WAREHOUSE_DSN", "valueFrom": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:sql-warden/warehouse"},
        {"name": "AUDIT_DSN", "valueFrom": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:sql-warden/audit"},
        {"name": "MASKING_KEY", "valueFrom": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:sql-warden/masking-key"}
      ],
      "healthCheck": {
        "command": ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"],
        "interval": 15,
        "timeout": 3,
        "startPeriod": 10
      },
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {"awslogs-group": "/sql-warden", "awslogs-region": "eu-west-1", "awslogs-stream-prefix": "sql-warden"}
      }
    }
  ]
}
```

Put the service behind an Application Load Balancer that terminates TLS and forwards only
`/mcp*`, with `/readyz` as the target group's health check. Its security group admits only
the load balancer on 8000; the warehouse's and the audit database's admit only sql-warden's
security group on 5432. A policy change is a new task definition revision (ECS has no way to
signal a running task), and the retention job a scheduled task with
`"command": ["audit", "prune", "--older-than", "90d"]`.

## 6. Before it takes traffic

- [ ] `sql-warden config validate --live` passes with the deployed config and secrets: every
      profile's role can only read and sees what its profile names, and the audit role can
      only add records.
- [ ] `audit.append_only: true` is set.
- [ ] `/readyz` is the readiness check, and only `/mcp` is reachable from outside.
- [ ] The databases admit only sql-warden (and the audit one, the retention job and readers).
- [ ] `sql_warden_audit_write_failures_total`, `sql_warden_config_last_reload_successful` and
      `/readyz` failures alert someone.
- [ ] The retention job runs, and `audit_prunes` shows it.
