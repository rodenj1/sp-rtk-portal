"""Accounts & login: the Authentik backend-for-frontend (ADR 0003).

- ``authentik``: drives the pinned login flow headlessly and completes OIDC
  code + PKCE server-side. Fails closed on anything it doesn't expect.
- ``store``: Portal accounts, keyed on ``(iss, sub)``.
- ``sessions``: the Portal session cookie and its rows.
- ``routes``: the login page, its JSON steps, and sign-out.
- ``deps``: ``current_account``, the dependency every signed-in page uses.
"""
