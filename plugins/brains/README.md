# Brain plugins

Each discovery/reasoning brain gets one directory here. The engine never imports
one directly; `crates/plugin-host` selects it behind the phase 0.3 contract.
`builtin-rules` is the planned first implementation and `ai-key` demonstrates
that an alternate reasoning brain has a first-class physical home.

No executable plugin or implied language boundary exists in phase 0.1.

