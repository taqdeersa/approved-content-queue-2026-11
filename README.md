# Approved encrypted content queue

This worker feeds one approved item per day to a server-side publisher. The content, configuration, account mapping and queue state are AES-256-GCM encrypted. Credentials are held in GitHub Actions Secrets.

Manual runs default to read-only verification. Publishing is limited to the approved November 2026 window and requires both repository variables and verified encrypted configuration. Ambiguous mutations halt without retrying. An accepted schedule is recorded separately from publication.

The workflow uses a standard public GitHub-hosted Linux runner, pinned dependencies, and no Actions artifacts or caches. It does not purchase credits, subscriptions or paid runner capacity.
