## Security

- Validate stored webhook destinations at the persistence boundary, reject malformed and internal targets for direct callers as well as the HTTP API, preserve explicit clear semantics, and reject omitted `url` fields without silently deleting the existing destination.
