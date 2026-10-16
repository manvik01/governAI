-- ZenAi4 0005: daily roll-up and the first report view (cost).
CREATE TABLE report.agent_day (
  day           date NOT NULL,
  observed_id   text NOT NULL,
  model         text NOT NULL DEFAULT '',
  runs          integer NOT NULL,
  steps         integer NOT NULL,
  failures      integer NOT NULL,
  p50_ms        integer,
  p95_ms        integer,
  input_tokens  bigint NOT NULL,
  output_tokens bigint NOT NULL,
  cost_usd      numeric(14,6) NOT NULL,
  unresolved_steps integer NOT NULL,
  PRIMARY KEY (day, observed_id, model)
);

CREATE VIEW report.cost AS
SELECT d.day,
       coalesce(a.name, 'unregistered: ' || o.key_value) AS agent,
       coalesce(a.business_unit, 'unowned')               AS team,
       d.model, d.input_tokens, d.output_tokens, d.cost_usd, d.unresolved_steps
FROM report.agent_day d
JOIN events.observed_agent o USING (observed_id)
LEFT JOIN control.agent a ON a.agent_id = o.agent_id;
