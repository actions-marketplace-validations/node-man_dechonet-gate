# DechoNet deploy gate

A GitHub Action that fails the job when the site you just deployed misses your
bar on HTTPS, the TLS certificate or security headers. It calls DechoNet's
public check (`/api/util/gate` — the same SSL and HTTP tools as
[dechonet.com](https://dechonet.com/util/golive)) and writes a table to the job
summary.

```yaml
- uses: node-man/dechonet-gate@v1
  with:
    url: https://example.com/
    min-ssl-grade: B        # A+ A B C D E F
    min-header-grade: C     # A+ A B C D E F
    min-cert-days: 14
    require-https: true
    api-key: ${{ secrets.DECHONET_API_KEY }}   # optional — your own rate limits
```

Run it after your deploy step, against the URL visitors reach.

## What it checks

| Check | Fails when |
|---|---|
| reachable | the page does not answer 2xx/3xx |
| https | the final page is served over plain HTTP (`require-https`) |
| ssl grade | the SSL grade is below `min-ssl-grade` |
| certificate days | the certificate expires in fewer than `min-cert-days` days |
| chain | the certificate chain is not trusted |
| header grade | the security-header grade is below `min-header-grade` |

A check DechoNet could not verify is reported as `unknown`. It does not fail the
job unless you set `fail-on-unknown: true`. If the SSL or HTTP lookup itself
fails, the gate fails — a lookup error is never a pass.

The gate clears DechoNet's cached SSL and HTTP results for the host before it
checks, so you see the site as it is right after the deploy.

## Inputs

| Input | Default | |
|---|---|---|
| `url` | — | Deployed URL to check (required) |
| `min-ssl-grade` | `B` | Lowest acceptable SSL grade |
| `min-header-grade` | `C` | Lowest acceptable security-header grade |
| `min-cert-days` | `14` | Minimum days before the certificate expires |
| `require-https` | `true` | Fail on a plain-HTTP final page |
| `api-key` | — | DechoNet API key (free, from your DechoNet account). Store it as a secret |
| `fail-on-unknown` | `false` | Also fail when a check could not be verified |
| `endpoint` | `https://dechonet.com` | API base URL |

Output: `pass` — `'true'` when every check passed.

Needs `bash`, `curl` and `jq`, which GitHub-hosted runners already have.

## Without the action

```bash
curl -s "https://dechonet.com/api/util/gate?url=https://example.com/&min_ssl=B&min_headers=C&min_days=14&require_https=1" | jq '.data.pass'
```

The [Go-live check](https://dechonet.com/util/golive) page builds this URL and a
ready-to-paste workflow step for the bar you pick.

## Limits

DechoNet only looks at what anyone can see from outside: the TLS handshake and
the response headers. A pass means the site met the bar you set, not that it is
secure. How DechoNet judges results and where it is wrong: https://dechonet.com/methodology

## Terms

From November 8, 2026, free use of the DechoNet API is for non-commercial
purposes. Running this gate regularly in a company's CI needs MCP·API Pro — see
https://dechonet.com/terms (section 4) or write to support@dechonet.com.

MIT licensed.
