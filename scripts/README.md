# Scripts

Only reusable project tools are kept under this directory. Runtime Lua files remain in
their original application directories and are not invoked from here.

| Path | Purpose |
| --- | --- |
| `build_release.sh` | Build the master and node Linux release archives. |
| `build_crawler_upgrade.sh` | Build the crawler-protection upgrade archive. |
| `preflight_check.sh` / `post_deploy_check.sh` | Validate master or node deployment before and after upgrade. |
| `upgrade/` | Files packaged into the crawler upgrade archive. |
| `deploy/` | Manual deployment helpers. They read local connection settings only. |
| `diagnostics/` | Reusable remote configuration and Nginx diagnostics. |
| `diagnostics/legacy/` | One-off historical troubleshooting scripts; retained for traceability, not part of normal deployment. |
| `tests/` | Manual DingTalk and Docker verification scripts. |

Local credentials belong in ignored `.zhongkui.private.env`; production package
parameters belong in ignored `.zhongkui.release.env`. Neither file is included in
release packages or Git commits.
