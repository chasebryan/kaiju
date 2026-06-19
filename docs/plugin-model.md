# Plugin Model

Kaiju's plugin model is currently a compile-time API skeleton. It is intended
to define boundaries before any untrusted plugin execution is introduced.

## Current Scope

The `kaiju-plugin-api` crate defines:

- plugin metadata
- capability declarations
- analysis pass plugin traits
- loader, architecture, and command plugin placeholders
- an in-process registry
- an example built-in analysis plugin

There is no dynamic loading, scripting bridge, C ABI, WASM runtime, or filesystem
access delegation in the current implementation.

## Safety Direction

Future plugin execution should be capability based and sandboxed. Preferred
directions are:

- WASM-hosted plugins for deterministic analysis extensions
- explicit capabilities for filesystem, network, and project mutation
- no default host access
- separate stable local ABI only after the Rust model settles

Native plugins may be useful later, but they should not be the first execution
model for untrusted extensions.

## Registration Shape

Plugins expose metadata and register capabilities through a registrar:

```rust
pub trait KaijuPlugin {
    fn metadata(&self) -> PluginMetadata;
    fn register(&self, registrar: &mut dyn PluginRegistrar) -> Result<()>;
}
```

The current example registers an analysis pass that can add a project fact.
This validates the boundary without claiming runtime plugin support.
