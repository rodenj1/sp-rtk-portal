"""Protocol version.

An integer, starting at 1 and independent of the sp-rtk-base version. It is
sent as a header on every poll, Check-in and tunnel open. Additive changes
don't bump it, and both sides ignore unknown fields.
"""

PROTOCOL_VERSION = 1
