"""Agent API: what the Portal agent calls, under ``/agent/``.

``auth.agent_request`` checks every request's proof (signed by a base key)
and protocol version. ``routes`` has the Claim endpoints so far; polls,
Check-ins and agent config come next (spec rodenj1/rtk_development#82).
"""
