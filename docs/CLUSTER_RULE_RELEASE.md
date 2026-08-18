# Cluster Rule Release

This release path is enabled only when both `centralized` and `master` are on.
Standalone mode keeps loading and reloading local files as before.

## Data flow

1. On the first cluster startup only, Master reads local rules and creates the initial MySQL release.
2. Later administrator changes are assembled as a candidate and stored in
   `waf_cluster_rule_release` with status `prepared` before they can become active.
3. A Redis transaction publishes the candidate snapshot, version, and legacy IP-list keys together.
4. Master marks the release `published`, materializes that exact MySQL snapshot to local files,
   and reloads Nginx.
5. If persistence or publishing fails, local candidate files are immediately restored from the
   previous MySQL `published` release and the API reports failure.
6. Nodes verify the snapshot hash, apply it in memory, and save `conf/.cluster/rules-lkg.json`.

Each new release also stores the complete editable rule source set: global and site rules,
white/black lists, site configuration, `website.json`, `ipgroup.json`, and `global.json`.
`system.json` and its role templates are never included.

The 10-second publish retry may promote a `prepared` candidate already durable in MySQL.
Startup restore and the 60-second integrity reconciliation read only the latest `published`
record. They never rebuild a release from local files, so stale files cannot overwrite Redis.

## Failure behavior

- MySQL unavailable: the change is not activated and the API reports publish failure.
- Redis unavailable: the durable `prepared` release remains in MySQL for timer retry.
- Redis succeeds but status update fails: the API reports failure; timer retry repairs status.
- Node cannot reach Redis: it keeps current memory rules and can restore the verified LKG file.
- Master restart: workers restore the last `published` runtime snapshot from MySQL.
- Master source hash differs from MySQL: worker 0 first backs up all local rule sources under
  `conf/.cluster/conflicts/<timestamp>/`, restores the latest published source set, and reloads
  Nginx. This includes missing, truncated, stale, and unexpected extra rule files.
- A matching source hash causes no file write and no reload.
- Legacy releases without a source-file archive can still restore IP white/black lists from
  their runtime snapshot.

## Compatibility

Redis key names and the node snapshot format remain compatible with older nodes.
The separate whitelist and blacklist Redis keys are generated from the same snapshot and
published in the same Redis transaction, preventing cross-version list combinations.
Concurrent publishers are serialized with a Redis lock.
