-- Demo warehouse for sql-warden. Run as the database owner on an empty database.
--
-- Deterministic: every value is derived from generate_series indexes, never random(),
-- so the data (and the planner's estimates) are the same on every machine.
--
--   products            200 rows   harmless catalogue
--   customers        10,000 rows   holds sensitive columns: email, phone, ssn
--   orders        1,000,000 rows   large enough that a bad query is genuinely expensive
--   employee_salaries   50 rows   never approved in the policy; the warden must refuse it

CREATE TABLE products (
    id          integer PRIMARY KEY,
    name        text    NOT NULL,
    category    text    NOT NULL,
    price_cents integer NOT NULL
);

INSERT INTO products (id, name, category, price_cents)
SELECT
    i,
    'Product ' || i,
    (ARRAY['books', 'electronics', 'garden', 'kitchen', 'toys'])[1 + i % 5],
    500 + (i * 137) % 20000
FROM generate_series(1, 200) AS i;

CREATE TABLE customers (
    id         integer     PRIMARY KEY,
    full_name  text        NOT NULL,
    email      text        NOT NULL UNIQUE,
    phone      text        NOT NULL,
    ssn        text        NOT NULL,
    country    text        NOT NULL,
    created_at timestamptz NOT NULL
);

INSERT INTO customers (id, full_name, email, phone, ssn, country, created_at)
SELECT
    i,
    (ARRAY['Ada', 'Grace', 'Alan', 'Edsger', 'Barbara', 'Donald', 'Frances', 'Ken'])[1 + i % 8]
        || ' ' || (ARRAY['Lovelace', 'Hopper', 'Turing', 'Dijkstra', 'Liskov', 'Knuth',
                         'Allen', 'Thompson', 'Ritchie', 'Hamilton'])[1 + (i / 8) % 10],
    'customer' || i || '@example.com',
    '+1-555-' || lpad(((i * 7919) % 10000)::text, 4, '0'),
    lpad(((i::bigint * 104729) % 1000)::text, 3, '0') || '-'
        || lpad(((i::bigint * 15485863) % 100)::text, 2, '0') || '-'
        || lpad(((i::bigint * 32452843) % 10000)::text, 4, '0'),
    (ARRAY['US', 'GB', 'DE', 'IN', 'JP', 'BR'])[1 + i % 6],
    timestamptz '2023-01-01 00:00:00+00' + (i * interval '47 minutes')
FROM generate_series(1, 10000) AS i;

CREATE TABLE orders (
    id          integer     PRIMARY KEY,
    customer_id integer     NOT NULL REFERENCES customers (id),
    product_id  integer     NOT NULL REFERENCES products (id),
    quantity    integer     NOT NULL,
    total_cents integer     NOT NULL,
    status      text        NOT NULL,
    ordered_at  timestamptz NOT NULL
);

INSERT INTO orders (id, customer_id, product_id, quantity, total_cents, status, ordered_at)
SELECT
    o.i,
    1 + (o.i * 7) % 10000,
    p.id,
    o.qty,
    o.qty * p.price_cents,
    (ARRAY['placed', 'shipped', 'delivered', 'delivered', 'returned'])[1 + o.i % 5],
    timestamptz '2024-01-01 00:00:00+00' + (o.i * interval '30 seconds')
FROM (
    SELECT i, 1 + i % 4 AS qty, 1 + (i * 31) % 200 AS product_id
    FROM generate_series(1, 1000000) AS i
) AS o
JOIN products AS p ON p.id = o.product_id;

CREATE INDEX orders_customer_id_idx ON orders (customer_id);
CREATE INDEX orders_ordered_at_idx ON orders (ordered_at);

CREATE TABLE employee_salaries (
    id            integer PRIMARY KEY,
    employee_name text    NOT NULL,
    title         text    NOT NULL,
    salary_cents  integer NOT NULL
);

INSERT INTO employee_salaries (id, employee_name, title, salary_cents)
SELECT
    i,
    'Employee ' || i,
    (ARRAY['Engineer', 'Analyst', 'Manager', 'Director'])[1 + i % 4],
    6000000 + (i * 98765) % 15000000
FROM generate_series(1, 50) AS i;

-- Planner statistics up front, so cost estimates are realistic from the first query.
ANALYZE;

-- The role sql-warden connects as. It can read every table, employee_salaries included:
-- keeping that table off-limits is the warden's job, and the demo should prove it.
-- It gets SELECT only, so writes fail on privileges even if a session turns off
-- default_transaction_read_only.
CREATE ROLE warden_reader LOGIN PASSWORD 'warden_reader';
ALTER ROLE warden_reader SET default_transaction_read_only = on;
GRANT USAGE ON SCHEMA public TO warden_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO warden_reader;

-- The role for the `public` profile: an agent released to customers. It can read only the
-- product catalog, and only these columns, so the database itself enforces what the profile
-- allows even if a check in front of it is wrong.
CREATE ROLE warden_public LOGIN PASSWORD 'warden_public';
ALTER ROLE warden_public SET default_transaction_read_only = on;
GRANT USAGE ON SCHEMA public TO warden_public;
GRANT SELECT (id, name, price_cents) ON products TO warden_public;
