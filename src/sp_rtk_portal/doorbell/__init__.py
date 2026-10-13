"""The Doorbell (ticket #100, ADR 0002): the HTTPS interface a Doorbell
server uses on the Portal, and the return paths and rings it carries.

The Doorbell server itself (on the NTRIP relay VPS) is not deployed in v1;
until it is, ``Settings.doorbell_token`` is empty and ``/doorbell/*``
answers 404. See the README for the interface."""
