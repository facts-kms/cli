# Control bearer token output.

`fact http token issue` can now write the secret token to `--output` / `-o`, creates credential files with 0600 permissions, and omits token secrets from JSON unless explicitly requested.

