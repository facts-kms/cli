# Remote Descriptors

Adds support for readable `fact-remote-v0` JSON descriptors carrying a remote
URL, ledger ID, genesis hash, and optional bearer token. `fact remote from FILE
[NAME]` configures or rotates remotes from a descriptor, and `fact clone --from
FILE` uses the same registration path before cloning. Descriptor consumers
verify the served ledger genesis hash before writing remote configuration.
