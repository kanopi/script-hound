# CircleCI

The included `.circleci/config.yml` defines a `scripthound` job that runs only when the pipeline parameter `run-fe-scan` is true or the trigger is a schedule, so it doesn't run on every push.

## Running it

**Scheduled:** go to Project Settings → Triggers → Add trigger (schedule). Pick the branch and cadence (for example daily) and add the pipeline parameter `run-fe-scan` = `true`.

**On demand:** go to Trigger Pipeline in the UI and add `run-fe-scan` = `true`. You can also use the API:

```bash
curl -X POST "https://circleci.com/api/v2/project/gh/<org>/<repo>/pipeline" \
  -H "Circle-Token: $CIRCLE_TOKEN" -H "Content-Type: application/json" \
  -d '{"branch":"main","parameters":{"run-fe-scan":true,"scan-urls":"https://example.com/,https://example.com/checkout"}}'
```

## Parameters

| Parameter | Effect |
|---|---|
| `run-fe-scan` | Must be `true` (or the trigger a schedule) for the scan to run. The name predates the ScriptHound rename and is kept so existing schedules keep working |
| `scan-urls` | Comma-separated URLs to scan instead of `sites.json` (handy for a one-off check) |
| `scan-site` | Scan one named site from `sites.json` |
| `scan-mode` | `url`, `crawl` or `sitemap` (empty = each site's own setting). See [Discovery modes](discovery.md) |
| `scan-sitemap` | Sitemap URL for sitemap mode |
| `scan-max-pages` | Page cap for crawl and sitemap modes |
| `fail-on` | `none` (default, report only), `high`, `medium` or `low` |

The job writes `html` and `md` reports, plus `report.json` (see [jq recipes](jq-recipes.md) for spreadsheets). To change any other setting, edit the job's `environment` block (see the env vars in the [command-line reference](configuration.md#command-line-reference)) or `sites.json`.

**Logged-in scans in CI:** keep credentials in CircleCI project environment variables or a context, never in the repo. Set `SCAN_COOKIES` or `SCAN_HEADERS` there, or use `${env:NAME}` in `sites.json`. A storage-state file holds live session cookies, so store it base64-encoded in an environment variable and write it to disk in a step before the scan (`echo "$AUTH_STATE_B64" | base64 -d > auth.json`). See [Logged-in scans](configuration.md#logged-in-scans).

Custom interactions deliberately aren't exposed as a pipeline parameter, because inline JavaScript would let anyone who can trigger a pipeline run code in the job. Commit them in `sites.json` or as files in the repo instead. See [Custom interactions](interactions.md).

## Results

Open the job's **Artifacts** tab → `scripthound/report.html`. Download `scripthound/report.json` and use the [jq recipes](jq-recipes.md) for spreadsheets. The Markdown summary is also printed in the job log. To get colored console output in the log, set `FORCE_COLOR=1` and add `console` to `SCAN_FORMAT`.

## Notes

- **Existing workflows.** If you add this to a repo that already has workflows, add `when: { not: << pipeline.parameters.run-fe-scan >> }` to them so a scan trigger doesn't run your builds too. A dedicated repo for the scanner avoids this.
- **Playwright version.** The Docker image tag in the job (`mcr.microsoft.com/playwright:v1.63.0-noble`) must match the `playwright` version in `package.json` and the `FROM` line in `Dockerfile`. Bump all three together.
- **Check edits.** After editing the config, run `circleci config validate`.
