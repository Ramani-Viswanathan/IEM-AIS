# ReferenceAgent

Reserved for Phase 3 of `Project DOCS/IEM-AIS-Platform-Evolution-Plan.md`
-- not built yet.

Will hold a small, honestly-labeled-as-toy local agent (stdlib HTTP
server, 3 fake tools, a minimal policy-decision gateway) that IEM-AIS's
`ExcessiveAgency` test case can attack through its existing
learn/send/classify pipeline, so "attack -> gateway decision -> blocked
-> evidence" becomes something actually demonstrable, without claiming
to intercept a real production agent deployment.

See the plan doc for the full design (server.py, agent.py, tools.py,
gateway/policy.py, gateway/rules.json, gateway/audit_log.py) before
adding anything here.
