"""Agent API: what the Portal agent calls, under ``/agent/``.

``auth.agent_request`` checks every request's proof (signed by a base key)
and protocol version (426 below ``Settings.min_protocol_version``).
``routes`` has the Claim endpoints, polls and Check-ins; ``config`` the
revisioned agent config block, notices and the latest release, which the
Portal owner edits on ``/settings`` (``settings_routes``).
"""
