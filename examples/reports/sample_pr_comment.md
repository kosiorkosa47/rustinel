## rustinel — supply-chain risk

▃ **0 → 24 (+24)** · MEDIUM · Decision: [review] **review required**

`[████░░░░░░░░░░░░░░░░]`  ·  policy: **balanced**  ·  5 packages

### Top risk contributors

- [med]  `openssl-sys@0.9.99` — crate name ends with \`-sys\`, a convention for native/FFI bindings
  - pulled in via: demo → openssl-sys
- [low]  `openssl-sys@0.9.99` — build.rs exists; the file was inspected statically and never executed
  - pulled in via: demo → openssl-sys

### Review required

- \`openssl-sys@0.9.99\` is a native/FFI dependency

### Suggested actions

- Review the native dependency and its build process before merging.
- Review the build script before merging.

<details>
<summary>Dependency changes</summary>

Added:

- `cc@1.0.83`
- `openssl-sys@0.9.99`
- `pkg-config@0.3.27`

Changed:

- none

Removed:

- none

</details>
