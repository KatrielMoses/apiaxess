# Phase 0.3 prior-art verification

All references are public/free context; none is a runtime dependency.

- [Nushell plugin protocol](https://www.nushell.sh/contributor-book/plugin_protocol_reference.html):
  executable plugins support stdio, negotiate encoding, and exchange `Hello`
  protocol/version metadata; a local socket is optional.
- [LSP specification](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/):
  initialization and exchanged capabilities inform the APIaxess handshake shape.
- [HashiCorp go-plugin](https://github.com/hashicorp/go-plugin): supervised local
  process RPC, version negotiation, structured logging, and crash isolation.
- [Zellij permissions](https://zellij.dev/documentation/plugin-api-permissions):
  current user-facing grants include state, files, commands, environment, and
  other privileged operations.
- [Zed extension development](https://zed.dev/docs/extensions/developing-extensions):
  Zed currently targets `wasm32-wasip2` and packages extensions with a manifest.
- [WIT specification](https://github.com/WebAssembly/component-model/blob/main/design/mvp/WIT.md):
  current feature gates define `@since`, opt-in `@unstable`, and deprecation.
- [Component Model repository](https://github.com/WebAssembly/component-model):
  stabilization is incremental; async and threads continue beyond Preview 2.
- [Frida modes](https://frida.re/docs/modes/): injected GumJS runs inside target
  processes with instrumentation access and is not a plugin trust boundary.

