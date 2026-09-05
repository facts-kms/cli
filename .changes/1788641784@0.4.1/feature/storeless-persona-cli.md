# Use storeless persona identity creation.

- Update `fact persona add` to use the SDK storeless persona identity API so new personas no longer create `identities/personas.sqlite`.
- Preserve existing store-backed persona records by falling back to their legacy identity store when no embedded bundle is present.



