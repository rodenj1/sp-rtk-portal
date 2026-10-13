"""Base proxy: the ``/b/<id>/s/<token>/`` rules (ADR 0004).

``middleware.BaseProxy`` serves everything under ``/b/``; ``rules`` holds the
header and path rules; ``relay`` carries a request or websocket down a tunnel
stream. ``middleware.frame_path(session)`` is the frame's URL.
"""
