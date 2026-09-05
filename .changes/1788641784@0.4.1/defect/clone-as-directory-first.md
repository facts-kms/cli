# Prefer ledger directory actors during writable clone.

- `fact clone --as` now resolves active ledger directory aliases before stale ledgerless actor registry entries.
- Ambiguous local actor registry matches now ask for an explicit actor ID.

