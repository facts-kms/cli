# Report missing local private key material in status.

- `fact status` now includes a stable `local_private_key_material` boolean for writable ledgers.
- Human status and write failures now point out missing private key material and recovery guidance.

