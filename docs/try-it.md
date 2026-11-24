# Try web-audit-workbench with synthetic fixtures

Requires Node.js 22 or later. No runtime dependencies or service credentials are needed.

```sh
node demo.mjs
node demo.mjs json > demo-report.json
node demo.mjs html > demo-report.html
```

The demo starts a temporary website on 127.0.0.1 and audits only that fixture. Do not interpret the results as an audit of a public website. Scan only targets you own or are authorized to assess.

The JSON report includes a `checks` array and explicitly identifies the synthetic demonstration. HTML is standalone and escapes untrusted report strings. Temporary fixture resources are cleaned up after the process ends.

## Install a published archive

Download the `.tgz` and `SHA256SUMS.txt` from this repository's GitHub release. Check the digest with `shasum -a 256 -c SHA256SUMS.txt` on macOS or `sha256sum -c SHA256SUMS.txt` on Linux. Install the verified tarball with `npm install ./ARCHIVE.tgz`. The archive includes `demo.mjs` and this walkthrough. This is a GitHub distribution; the package has not been published to the npm registry.

## Reproduce the checks

```sh
npm run check
npm test
```

CI runs Node 22 and 24 on Linux, macOS and Windows. GitHub publication requires the complete matrix to pass for the exact main-branch source commit. Daily scheduled checks run without changing files or creating a release.
