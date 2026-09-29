# Repository map

```text
apps/
  engine/                 native composition root
  gui/                    TypeScript local web client
crates/
  api-model/              canonical facts, provenance, merge state, serialization
  diagnostics/            canonical stable-ID what/why/fix diagnostics
  engine-shell/           core orchestration shell consuming the canonical model
  local-api/              loopback HTTP/static-asset transport
  plugin-host/            only engine-facing plugin seam
  external-tools/         only external process/tool adapter boundary
  host-capabilities/      capability declaration/detection seam
  install-layout/         one resolver for bundled-resource and per-user data paths
  sandbox/                local or remote sandbox backend port
  session/                scope, lifecycle, audit, workbench slot, durable envelope
  workbench-proxy/        future interception/TLS core
plugins/
  brains/
    builtin-rules/        first discovery-brain implementation home
    ai-key/               reserved alternate brain home
  targets/
    apk/                  first target implementation home
    web/ exe/ deb/        reserved future target homes
packaging/
  debian/ windows/        future native package inputs
  assets/                 heavy-asset manifest/installer home, not asset payloads
xtask/                    repository policy checks
```

Dependencies point inward through ports: implementations depend on contracts;
the engine does not depend on concrete plugins, tools, or sandbox backends. The
engine consumes the canonical session and diagnostic crates; local API payloads
must adapt those values rather than becoming a second domain model.
