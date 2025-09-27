insert into session_policy (id, name, condition_type, condition_value, effect, priority, active)
values
  (1, 'tenant1 off-hour deny', 'TIME_WINDOW', '{"start":"20:00","end":"06:00","zone":"Asia/Seoul"}', 'DENY', 120, true),
  (2, 'tenant1 business hours allow', 'TIME_WINDOW', '{"start":"06:00","end":"20:00","zone":"Asia/Seoul"}', 'ALLOW', 90, true),
  (3, 'tenant1 engineering ip allow', 'IP_RANGE', '{"cidr":["10.0.0.0/8","192.168.0.0/16"]}', 'ALLOW', 110, true),
  (4, 'tenant1 block restricted country', 'LOCATION', '{"countries":["CN","RU"]}', 'DENY', 130, true),
  (5, 'tenant2 office allow', 'TIME_WINDOW', '{"start":"08:00","end":"18:00","zone":"UTC"}', 'ALLOW', 90, true),
  (6, 'tenant2 blacklist user', 'LOCATION', '{"countries":["KR"]}', 'DENY', 140, true);

insert into session_policy_scope (id, scope_type, scope_value, policy_id, excluded)
values
  (1, 'TENANT', 'tenant1', 1, false),
  (2, 'TENANT', 'tenant1', 2, false),
  (3, 'TENANT', 'tenant1', 3, false),
  (4, 'GROUP', 'engineering', 3, false),
  (5, 'TENANT', 'tenant1', 4, false),
  (6, 'TENANT', 'tenant2', 5, false),
  (7, 'TENANT', 'tenant2', 6, false),
  (8, 'USER', 'blacklist-user', 6, false);

insert into tenant_session_limit (tenant_id, max_sessions, max_idle_seconds, max_duration_seconds)
values
  ('tenant1', 3, 1200, 7200),
  ('tenant2', 2, 900, 3600);
