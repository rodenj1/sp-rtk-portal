"""Shares: an Operator gives another account full remote access to a base.

- ``sharing``: Share by email (Share or Pending share), conversion at login,
  remove, leave, withdraw; audit and email.
- ``store``: the ``share`` and ``pending_share`` rows.
- ``routes``: the base's Shares page and its actions.

Access checks read Shares through ``bases.store.reachable_by`` (``.role`` is
``"operator"`` or ``"shared"``).
"""
