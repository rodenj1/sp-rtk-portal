# sp-rtk-portal-protocol

The agent-to-Portal protocol, published from the `sp-rtk-portal` repo so the Portal and sp-rtk-base's Portal agent share one definition: message shapes, request signing and verification, tunnel framing, and the protocol version.

For now it holds only `PROTOCOL_VERSION`.

sp-rtk-base depends on it as a Git subdirectory dependency:

```toml
[project]
dependencies = ["sp-rtk-portal-protocol"]

[tool.uv.sources]
sp-rtk-portal-protocol = { git = "https://github.com/rodenj1/sp-rtk-portal", subdirectory = "protocol", rev = "<commit or tag>" }
```

For local development against a checkout next to it, use `{ path = "../sp-rtk-portal/protocol", editable = true }` instead.
