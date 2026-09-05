# Remote Add Advertised Ledger

`fact remote add --ledger NAME` now falls back to the remote discovery endpoint
when `NAME` is not a local ledger reference, allowing it to match a ledger
namespace advertised by the remote and store the corresponding ledger ID.
