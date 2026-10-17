# Signal — Threat Intelligence Dashboard

A static, responsive dashboard for monitoring CISA's Known Exploited Vulnerabilities (KEV) catalog. It uses the public catalog, refreshes every five minutes, and caches the latest successful response in the browser for offline viewing.

## Features

- Current KEV catalog count, monthly additions, and ransomware-linked entries
- Search across CVE IDs, vendors, products, and vulnerability names
- Filter by vendor or known ransomware use; sort by catalog date or vendor
- Recent additions chart, CVE record links, and CSV export
- Five-minute polling, manual refresh, source health indicator, and local cache
- Static files only; no build step, API key, or server required

## Run locally

Open `index.html` in a browser. If the browser blocks requests from a `file://` page, serve the folder with any static HTTP server, for example:

```sh
python -m http.server 8000
```

Then open `http://localhost:8000`.

## Publish with GitHub Pages

1. Create an empty GitHub repository and push this project.
2. In the repository, open **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select the default branch and `/ (root)`, then save.
4. Open the Pages URL GitHub provides.

The repository is ready for a later push; no remote or credentials are configured here.

## Data and refresh behavior

The dashboard first requests CISA's JSON catalog and falls back to the CISA-maintained [`cisagov/kev-data`](https://github.com/cisagov/kev-data) mirror if the primary endpoint is unavailable. The mirror is updated when CISA changes the catalog and is expected to synchronize shortly afterward. Five-minute polling checks for catalog changes; it does not mean new threat observations arrive every five minutes. The catalog itself is generally updated on weekdays when there are new or changed entries.

The ransomware figure reflects CISA's `knownRansomwareCampaignUse` field. A value of “No known use” means CISA has not confirmed use in a ransomware campaign; it does not establish that no such use exists. The catalog is vulnerability intelligence, not a live incident or network telemetry feed.

The browser stores the most recently retrieved catalog in local storage. If both feeds are unreachable, the dashboard displays that cached copy and marks the connection as offline. Live data requires an internet connection and the browser must permit cross-origin requests to the public feed.

## Project files

- `index.html` — page structure
- `styles.css` — layout and responsive styling
- `app.js` — feed refresh, cache, filtering, chart, and CSV export

