-- Data model (design §6). Every statement is idempotent-safe only through the migration ledger.
CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE org_kind AS ENUM ('maker', 'customer', 'recipient');
CREATE TYPE enterprise_size AS ENUM ('micro', 'small', 'medium', 'large');
CREATE TYPE data_type AS ENUM ('number', 'boolean', 'string');
CREATE TYPE catalogue_status AS ENUM ('draft', 'published');
CREATE TYPE request_state AS ENUM ('received', 'evaluated', 'granted', 'withheld', 'refused');
CREATE TYPE document_status AS ENUM ('draft', 'approved');

CREATE TABLE recipient_category (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL UNIQUE,
  terms_template_id text NOT NULL,
  terms_template_version text NOT NULL,
  -- Art. 9 compensation schedule, identical for every recipient in the category (Art. 8(3))
  formatting_cents integer NOT NULL CHECK (formatting_cents >= 0),
  dissemination_cents integer NOT NULL CHECK (dissemination_cents >= 0),
  storage_cents integer NOT NULL CHECK (storage_cents >= 0),
  investment_share_cents integer NOT NULL CHECK (investment_share_cents >= 0),
  margin_rate numeric(6,4) NOT NULL CHECK (margin_rate >= 0)
);

CREATE TABLE organisation (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  kind org_kind NOT NULL,
  sme_flag boolean NOT NULL DEFAULT false,                  -- Art. 9(4) cost cap for recipients
  non_profit_research boolean NOT NULL DEFAULT false,       -- Art. 9(4)
  has_non_sme_partner_or_linked boolean NOT NULL DEFAULT false,
  group_identifier text,                                     -- matched against the gatekeeper list (R13)
  recipient_category_id uuid REFERENCES recipient_category(id),
  -- Maker profile (Art. 7): only meaningful for kind = 'maker'
  size enterprise_size,
  subcontracted boolean NOT NULL DEFAULT false,
  medium_since date,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (kind <> 'recipient' OR recipient_category_id IS NOT NULL OR verified_at IS NULL)
);

CREATE TABLE principal (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES organisation(id),
  oidc_sub text NOT NULL UNIQUE,
  machine_client boolean NOT NULL DEFAULT false,   -- OAuth client-credentials client (design §5.7)
  roles text[] NOT NULL CHECK (roles <@ ARRAY['maker_admin','catalogue_reviewer','legal_officer','customer_admin','customer_user','recipient']::text[] AND cardinality(roles) > 0),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE product_model (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  maker_org_id uuid NOT NULL REFERENCES organisation(id),
  name text NOT NULL,
  placed_on_market_at date,
  maker_size_at_placement enterprise_size,
  catalogue_version integer NOT NULL DEFAULT 0,
  related_service jsonb,                       -- Art. 3(3) facts supplied by the maker's legal officer
  UNIQUE (maker_org_id, name)
);

CREATE TABLE datapoint (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_id uuid NOT NULL REFERENCES product_model(id),
  name text NOT NULL,
  source_address text NOT NULL,                 -- OPC UA NodeId or tag address
  dtype data_type NOT NULL,
  description text,
  unit_ucum text,
  rate_hz double precision CHECK (rate_hz IS NULL OR rate_hz > 0),
  est_bytes_per_day bigint CHECK (est_bytes_per_day IS NULL OR est_bytes_per_day >= 0),
  trade_secret boolean NOT NULL DEFAULT false,
  ts_holder text,                               -- trade secret holder, if not the maker (Art. 3(3)(h))
  personal_data boolean NOT NULL DEFAULT false,
  personal_category text,
  retention_days integer CHECK (retention_days IS NULL OR retention_days > 0),
  draft_description text,                       -- LLM suggestions, never published without review
  draft_unit_ucum text,
  status catalogue_status NOT NULL DEFAULT 'draft',
  version integer NOT NULL DEFAULT 0,
  reviewed_by uuid REFERENCES principal(id),
  reviewed_at timestamptz,
  UNIQUE (model_id, source_address),
  CHECK (status = 'draft' OR (description IS NOT NULL AND reviewed_by IS NOT NULL)),
  CHECK (NOT trade_secret OR status = 'draft' OR ts_holder IS NOT NULL),
  CHECK (NOT personal_data OR status = 'draft' OR personal_category IS NOT NULL)
);

CREATE TABLE catalogue_version (
  model_id uuid NOT NULL REFERENCES product_model(id),
  version integer NOT NULL,
  snapshot jsonb NOT NULL,
  published_by uuid NOT NULL REFERENCES principal(id),
  published_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (model_id, version)
);

CREATE TABLE machine (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  serial text NOT NULL,
  model_id uuid NOT NULL REFERENCES product_model(id),
  owner_org_id uuid REFERENCES organisation(id),
  linked_at timestamptz,
  link_evidence_ref text,
  UNIQUE (model_id, serial),
  CHECK ((owner_org_id IS NULL) = (linked_at IS NULL))
);

CREATE TABLE device (
  id text PRIMARY KEY,                          -- certificate CN, used as MQTT username
  machine_id uuid NOT NULL UNIQUE REFERENCES machine(id),
  last_seq bigint NOT NULL DEFAULT -1           -- the connector publishes in order (QoS 1), so seq <= last_seq is a duplicate
);

CREATE TABLE link_request (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_org_id uuid NOT NULL REFERENCES organisation(id),
  model_id uuid NOT NULL REFERENCES product_model(id),
  serial text NOT NULL,
  evidence_ref text NOT NULL,                   -- invoice number or document reference (R6: nothing more)
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_by uuid REFERENCES principal(id),
  reviewed_at timestamptz
);

CREATE TABLE reading (
  machine_id uuid NOT NULL,
  datapoint_id uuid NOT NULL,
  ts timestamptz NOT NULL,
  num double precision,
  bool boolean,
  txt text,
  CHECK (num_nonnulls(num, bool, txt) = 1)
);
SELECT create_hypertable('reading', by_range('ts'));
CREATE UNIQUE INDEX reading_uq ON reading (machine_id, datapoint_id, ts);

CREATE TABLE reading_secret (                   -- trade-secret values, envelope-encrypted (design §5.3)
  machine_id uuid NOT NULL,
  datapoint_id uuid NOT NULL,
  ts timestamptz NOT NULL,
  sealed bytea NOT NULL
);
SELECT create_hypertable('reading_secret', by_range('ts'));
CREATE UNIQUE INDEX reading_secret_uq ON reading_secret (machine_id, datapoint_id, ts);

CREATE TABLE data_key (
  datapoint_id uuid PRIMARY KEY REFERENCES datapoint(id),
  kek_id text NOT NULL,
  wrapped bytea NOT NULL
);

CREATE TABLE quarantine (
  id bigserial PRIMARY KEY,
  device_id text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL,
  payload jsonb NOT NULL
);

CREATE TABLE document (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL,
  template_id text NOT NULL,
  template_version text NOT NULL,
  subject jsonb NOT NULL,                       -- what the document is about (model, request, contract parties)
  content jsonb NOT NULL,                       -- machine-readable rendering
  pdf bytea NOT NULL,                           -- PDF/UA rendering
  sha256 text NOT NULL,
  status document_status NOT NULL DEFAULT 'draft',
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_by uuid REFERENCES principal(id),
  approved_at timestamptz,
  CHECK ((status = 'approved') = (approved_by IS NOT NULL))
);

CREATE TABLE contract (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('data_use', 'nda', 'recipient_terms')),
  template_id text NOT NULL,
  template_version text NOT NULL,
  org_id uuid NOT NULL REFERENCES organisation(id),            -- accepting party
  counterparty_org_id uuid NOT NULL REFERENCES organisation(id),
  datapoint_ids uuid[] NOT NULL DEFAULT '{}',                    -- NDA coverage (R7)
  document_id uuid NOT NULL REFERENCES document(id),
  doc_sha256 text NOT NULL,
  accepted_by uuid NOT NULL REFERENCES principal(id),
  accepted_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE legal_basis (                      -- GDPR basis for releasing personal data (R9)
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_org_id uuid NOT NULL REFERENCES organisation(id),
  datapoint_id uuid NOT NULL REFERENCES datapoint(id),
  basis text NOT NULL,
  recorded_by uuid NOT NULL REFERENCES principal(id),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (customer_org_id, datapoint_id)
);

CREATE TABLE "grant" (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_org_id uuid NOT NULL REFERENCES organisation(id),
  recipient_org_id uuid NOT NULL REFERENCES organisation(id),
  datapoint_ids uuid[] NOT NULL CHECK (cardinality(datapoint_ids) > 0),
  channels text[] NOT NULL CHECK (cardinality(channels) > 0 AND channels <@ ARRAY['rest','sse','webhook','mqtt']::text[]),
  purpose text NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  compensation jsonb NOT NULL,                  -- Art. 9 quote incl. calculation basis
  created_by uuid NOT NULL REFERENCES principal(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (customer_org_id <> recipient_org_id)
);

CREATE TABLE webhook_endpoint (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  grant_id uuid NOT NULL REFERENCES "grant"(id),
  url text NOT NULL CHECK (url LIKE 'https://%'),
  secret_sealed bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

CREATE TABLE webhook_delivery (
  id bigserial PRIMARY KEY,
  endpoint_id uuid NOT NULL REFERENCES webhook_endpoint(id),
  payload jsonb NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  last_error text
);
CREATE INDEX webhook_delivery_due ON webhook_delivery (next_attempt_at) WHERE delivered_at IS NULL;

CREATE TABLE request (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('access', 'share')),
  requester_principal_id uuid NOT NULL REFERENCES principal(id),
  requester_org_id uuid NOT NULL REFERENCES organisation(id),
  machine_id uuid NOT NULL REFERENCES machine(id),
  datapoint_ids uuid[] NOT NULL,
  recipient_org_id uuid REFERENCES organisation(id),
  state request_state NOT NULL DEFAULT 'received',
  received_at timestamptz NOT NULL DEFAULT now(),
  due_at timestamptz NOT NULL,
  alerted_50 boolean NOT NULL DEFAULT false,
  alerted_90 boolean NOT NULL DEFAULT false,
  decided_at timestamptz,
  CHECK ((kind = 'share') = (recipient_org_id IS NOT NULL))
);

CREATE TABLE decision (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES request(id),
  outcome request_state NOT NULL CHECK (outcome IN ('granted', 'withheld', 'refused')),
  ground text,
  justification text NOT NULL,
  datapoint_ids uuid[] NOT NULL,
  letter_document_id uuid REFERENCES document(id),
  authority_document_id uuid REFERENCES document(id),
  decided_by uuid REFERENCES principal(id),     -- NULL only for automatic grants by the policy decision point
  decided_at timestamptz NOT NULL DEFAULT now(),
  CHECK (outcome = 'granted' OR (ground IS NOT NULL AND decided_by IS NOT NULL
    AND letter_document_id IS NOT NULL AND authority_document_id IS NOT NULL))
);

CREATE TABLE notification (
  id bigserial PRIMARY KEY,
  kind text NOT NULL,
  ref_id uuid NOT NULL,
  message text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE access_log (                       -- minimal by design (R6, Art. 4(5)): no IP, no query contents
  id bigserial PRIMARY KEY,
  principal_id uuid NOT NULL,
  request_id uuid,
  ts timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_log_ts ON access_log (ts);

-- ── Row-level security: defence in depth behind the policy decision point (design §5.3) ──
-- The application sets app.scope ('system' | 'maker' | 'customer' | 'recipient') and app.org_id per
-- transaction. Without them nothing is visible. FORCE applies the policies to the table owner too.
CREATE FUNCTION app_scope() RETURNS text LANGUAGE sql STABLE AS $$ SELECT current_setting('app.scope', true) $$;
CREATE FUNCTION app_org() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('app.org_id', true), '')::uuid $$;
CREATE FUNCTION recipient_may_read(m_owner uuid, dp uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM "grant" g WHERE g.customer_org_id = m_owner AND g.recipient_org_id = app_org()
    AND g.revoked_at IS NULL AND g.expires_at > now() AND (dp IS NULL OR dp = ANY (g.datapoint_ids)))
$$;

ALTER TABLE machine ENABLE ROW LEVEL SECURITY;
ALTER TABLE machine FORCE ROW LEVEL SECURITY;
CREATE POLICY machine_access ON machine USING (
  app_scope() IN ('system', 'maker')
  OR (app_scope() = 'customer' AND owner_org_id = app_org())
  OR (app_scope() = 'recipient' AND recipient_may_read(owner_org_id, NULL))
);

ALTER TABLE reading ENABLE ROW LEVEL SECURITY;
ALTER TABLE reading FORCE ROW LEVEL SECURITY;
CREATE POLICY reading_access ON reading USING (
  app_scope() IN ('system', 'maker')
  OR EXISTS (SELECT 1 FROM machine m WHERE m.id = reading.machine_id AND (
    (app_scope() = 'customer' AND m.owner_org_id = app_org())
    OR (app_scope() = 'recipient' AND recipient_may_read(m.owner_org_id, reading.datapoint_id))))
);

ALTER TABLE reading_secret ENABLE ROW LEVEL SECURITY;
ALTER TABLE reading_secret FORCE ROW LEVEL SECURITY;
CREATE POLICY reading_secret_access ON reading_secret USING (
  app_scope() IN ('system', 'maker')
  OR EXISTS (SELECT 1 FROM machine m WHERE m.id = reading_secret.machine_id AND (
    (app_scope() = 'customer' AND m.owner_org_id = app_org())
    OR (app_scope() = 'recipient' AND recipient_may_read(m.owner_org_id, reading_secret.datapoint_id))))
);

-- Compression after 7 days (design §5.3, §10).
ALTER TABLE reading SET (timescaledb.compress, timescaledb.compress_segmentby = 'machine_id, datapoint_id');
SELECT add_compression_policy('reading', INTERVAL '7 days');
ALTER TABLE reading_secret SET (timescaledb.compress, timescaledb.compress_segmentby = 'machine_id, datapoint_id');
SELECT add_compression_policy('reading_secret', INTERVAL '7 days');
