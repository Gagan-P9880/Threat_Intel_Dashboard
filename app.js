const FEEDS = [
  { name: 'CISA KEV Catalog', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  { name: 'CISA KEV GitHub mirror', url: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json' }
];
const REFRESH_MS = 5 * 60 * 1000;
const CACHE_KEY = 'signal-kev-cache-v1';
const $ = (selector) => document.querySelector(selector);
const state = { entries: [], catalog: null, query: '', vendor: '', sort: 'newest', onlyRansomware: false, timer: null, toastTimer: null };

function escapeHtml(value = '') {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}
function dateOnly(value) { const date = new Date(`${value}T00:00:00Z`); return Number.isNaN(date.getTime()) ? null : date; }
function formatDate(value) {
  const date = dateOnly(value);
  return date ? new Intl.DateTimeFormat('en', { day: '2-digit', month: 'short', year: '2-digit', timeZone: 'UTC' }).format(date) : '—';
}
function ageLabel(dateValue) {
  const date = new Date(dateValue);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  const mins = Math.max(0, Math.floor((Date.now() - date.getTime()) / 60000));
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
function showToast(message) {
  const toast = $('#toast'); toast.textContent = message; toast.classList.add('show');
  clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => toast.classList.remove('show'), 2600);
}
function setConnection(ok, message) {
  $('#source-status').textContent = message;
  $('#source-status-indicator').className = `status-indicator ${ok ? 'online' : 'error'}`;
  $('#sidebar-status').className = `mini-status ${ok ? 'online' : 'error'}`;
  $('#connected-icon').textContent = ok ? '●' : '!';
  $('#connected-icon').style.color = ok ? 'var(--green)' : 'var(--orange)';
}
function normalizeCatalog(data) {
  if (!data || !Array.isArray(data.vulnerabilities)) throw new Error('Unexpected catalog format');
  return {
    catalogVersion: data.catalogVersion || '—', dateReleased: data.dateReleased || null,
    count: Number.isFinite(Number(data.count)) ? Number(data.count) : data.vulnerabilities.length,
    vulnerabilities: data.vulnerabilities
  };
}
async function fetchJson(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { cache: 'no-store', signal: controller.signal, headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally { clearTimeout(timeout); }
}
function cacheCatalog(catalog) {
  try { localStorage.setItem(CACHE_KEY, JSON.stringify({ savedAt: Date.now(), catalog })); } catch { /* Storage may be disabled. */ }
}
function loadCache() {
  try { const saved = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null'); return saved?.catalog ? saved : null; } catch { return null; }
}
async function refresh({ manual = false } = {}) {
  const button = $('#refresh-button'); button.classList.add('spinning');
  let lastError;
  for (const feed of FEEDS) {
    try {
      const catalog = normalizeCatalog(await fetchJson(feed.url));
      state.catalog = catalog;
      state.entries = catalog.vulnerabilities;
      state.cachedAt = Date.now();
      state.feedName = feed.name;
      cacheCatalog(catalog);
      setConnection(true, `Live · ${feed.name}`);
      render();
      if (manual) showToast('Catalog refreshed from the public feed');
      button.classList.remove('spinning');
      return;
    } catch (error) { lastError = error; }
  }
  const cached = loadCache();
  if (cached) {
    state.catalog = cached.catalog; state.entries = cached.catalog.vulnerabilities; state.cachedAt = cached.savedAt;
    setConnection(false, `Offline · cached ${ageLabel(cached.savedAt)}`); render();
    $('#updated-at').textContent = `Cached data · saved ${ageLabel(cached.savedAt)}`;
  } else {
    setConnection(false, 'Feed unavailable · retrying');
    $('#updated-at').textContent = 'Could not connect · retrying automatically';
    $('#vulnerability-rows').innerHTML = `<tr><td colspan="6" class="empty-cell">Could not load the public catalog. Check your connection and refresh.</td></tr>`;
  }
  button.classList.remove('spinning');
  if (manual) showToast(lastError?.name === 'AbortError' ? 'Feed request timed out. Please try again.' : 'Could not reach the public feed.');
}
function filteredEntries() {
  const needle = state.query.trim().toLowerCase();
  let entries = state.entries.filter((entry) => {
    const searchText = [entry.cveID, entry.vendorProject, entry.product, entry.vulnerabilityName, entry.shortDescription].join(' ').toLowerCase();
    return (!needle || searchText.includes(needle)) && (!state.vendor || entry.vendorProject === state.vendor) && (!state.onlyRansomware || entry.knownRansomwareCampaignUse === 'Known');
  });
  entries.sort((a, b) => {
    if (state.sort === 'oldest') return String(a.dateAdded).localeCompare(String(b.dateAdded));
    if (state.sort === 'vendor') return String(a.vendorProject).localeCompare(String(b.vendorProject)) || String(b.dateAdded).localeCompare(String(a.dateAdded));
    if (state.sort === 'ransomware') return Number(b.knownRansomwareCampaignUse === 'Known') - Number(a.knownRansomwareCampaignUse === 'Known') || String(b.dateAdded).localeCompare(String(a.dateAdded));
    return String(b.dateAdded).localeCompare(String(a.dateAdded));
  });
  return entries;
}
function updateVendorFilter() {
  const select = $('#vendor-filter'); const current = state.vendor;
  const vendors = [...new Set(state.entries.map((entry) => entry.vendorProject).filter(Boolean))].sort((a, b) => a.localeCompare(b));
  select.innerHTML = '<option value="">All vendors</option>' + vendors.map((vendor) => `<option value="${escapeHtml(vendor)}">${escapeHtml(vendor)}</option>`).join('');
  select.value = current;
}
function renderRows(entries) {
  const rows = $('#vulnerability-rows');
  if (!entries.length) {
    rows.innerHTML = `<tr><td colspan="6" class="empty-cell">${state.entries.length ? 'No vulnerabilities match these filters.' : 'No catalog entries available.'}</td></tr>`;
    return;
  }
  rows.innerHTML = entries.slice(0, 250).map((entry) => {
    const cve = escapeHtml(entry.cveID || 'Unknown CVE');
    const ransomware = entry.knownRansomwareCampaignUse === 'Known';
    const dueClass = dateOnly(entry.dueDate) && dateOnly(entry.dueDate) < new Date() ? ' style="color:#ef9999"' : '';
    return `<tr>
      <td class="cell-vulnerability" data-label="Vulnerability"><a class="cve-link" href="https://www.cve.org/CVERecord?id=${encodeURIComponent(entry.cveID || '')}" target="_blank" rel="noreferrer">${cve}</a><span class="vuln-name" title="${escapeHtml(entry.vulnerabilityName || '')}">${escapeHtml(entry.vulnerabilityName || entry.shortDescription || 'Known exploited vulnerability')}</span></td>
      <td class="cell-vendor" data-label="Vendor / product"><span class="vendor-name">${escapeHtml(entry.vendorProject || 'Unknown')}</span><span class="product-name">${escapeHtml(entry.product || '—')}</span></td>
      <td class="date-cell cell-added" data-label="Added to CISA catalog">${formatDate(entry.dateAdded)}</td>
      <td class="cell-ransomware" data-label="Ransomware use">${ransomware ? '<span class="ransomware-badge">Known</span>' : '<span class="no-ransomware">Not confirmed</span>'}</td>
      <td class="date-cell cell-due" data-label="Remediation due date"${dueClass}>${formatDate(entry.dueDate)}</td>
      <td class="cell-action"><button class="row-detail" title="Open CVE record" aria-label="Open ${cve} record" data-cve="${cve}">↗</button></td>
    </tr>`;
  }).join('');
}
function renderChart() {
  const days = Array.from({ length: 30 }, (_, index) => {
    const date = new Date(); date.setUTCHours(0, 0, 0, 0); date.setUTCDate(date.getUTCDate() - (29 - index));
    const key = date.toISOString().slice(0, 10);
    return { key, date, count: 0 };
  });
  const byDate = new Map(days.map((day) => [day.key, day]));
  state.entries.forEach((entry) => { const key = entry.dateAdded; if (byDate.has(key)) byDate.get(key).count += 1; });
  const max = Math.max(1, ...days.map((day) => day.count));
  $('#pulse-chart').innerHTML = days.map((day) => {
    const height = day.count ? Math.max(7, Math.round((day.count / max) * 100)) : 2;
    return `<span class="chart-bar" style="--height:${height}%" title="${day.key}: ${day.count} added"></span>`;
  }).join('');
  const sum = days.reduce((total, day) => total + day.count, 0);
  $('#chart-total').textContent = sum.toLocaleString();
  $('#chart-date-range').textContent = `${days[0].key.slice(5)} — ${days.at(-1).key.slice(5)}`;
}
function render() {
  if (!state.catalog) return;
  updateVendorFilter();
  const entries = filteredEntries();
  const ransomwareCount = state.entries.filter((entry) => entry.knownRansomwareCampaignUse === 'Known').length;
  const now = new Date();
  const monthPrefix = `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
  const monthCount = state.entries.filter((entry) => String(entry.dateAdded || '').startsWith(monthPrefix)).length;
  $('#metric-total').textContent = Number(state.catalog.count || state.entries.length).toLocaleString();
  $('#metric-month').textContent = monthCount.toLocaleString();
  $('#month-label').textContent = `Added in ${new Intl.DateTimeFormat('en', { month: 'long', timeZone: 'UTC' }).format(now)} (UTC)`;
  $('#metric-ransomware').textContent = ransomwareCount.toLocaleString();
  $('#metric-freshness').textContent = ageLabel(state.cachedAt || Date.now());
  $('#ransomware-progress').style.width = `${state.entries.length ? Math.min(100, ransomwareCount / state.entries.length * 100) : 0}%`;
  $('#catalog-date').textContent = state.catalog.dateReleased ? new Intl.DateTimeFormat('en', { year: 'numeric', month: 'short', day: '2-digit', timeZone: 'UTC' }).format(new Date(state.catalog.dateReleased)) : 'Not provided';
  $('#updated-at').textContent = `Updated ${ageLabel(state.catalog.dateReleased || state.cachedAt || Date.now())}`;
  $('#refresh-label').textContent = 'Auto-refresh every 5 min';
  $('#visible-count').textContent = entries.length.toLocaleString();
  $('#result-summary').textContent = `Showing ${Math.min(entries.length, 250).toLocaleString()} of ${entries.length.toLocaleString()} matching · ${state.entries.length.toLocaleString()} total`;
  $('#focus-count').textContent = ransomwareCount.toLocaleString();
  renderRows(entries);
  renderChart();
}
function exportCsv() {
  const rows = filteredEntries();
  if (!rows.length) { showToast('No matching entries to export'); return; }
  const columns = ['cveID', 'vendorProject', 'product', 'vulnerabilityName', 'dateAdded', 'shortDescription', 'knownRansomwareCampaignUse', 'requiredAction', 'dueDate', 'notes'];
  const csv = [columns.join(','), ...rows.map((entry) => columns.map((key) => `"${String(entry[key] ?? '').replace(/"/g, '""')}"`).join(','))].join('\r\n');
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
  anchor.href = url; anchor.download = `signal-kev-${new Date().toISOString().slice(0, 10)}.csv`; anchor.click(); URL.revokeObjectURL(url);
  showToast(`Exported ${rows.length.toLocaleString()} catalog entries`);
}
function tickClock() {
  $('#clock').textContent = `${new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'UTC' }).format(new Date())} UTC`;
  $('#footer-year').textContent = new Date().getUTCFullYear();
  if (state.catalog && state.cachedAt) $('#metric-freshness').textContent = ageLabel(state.cachedAt);
}
$('#search-input').addEventListener('input', (event) => { state.query = event.target.value; const matching = filteredEntries(); renderRows(matching); $('#visible-count').textContent = matching.length.toLocaleString(); $('#result-summary').textContent = `Showing ${Math.min(matching.length, 250).toLocaleString()} of ${matching.length.toLocaleString()} matching · ${state.entries.length.toLocaleString()} total`; });
$('#vendor-filter').addEventListener('change', (event) => { state.vendor = event.target.value; render(); });
$('#sort-filter').addEventListener('change', (event) => { state.sort = event.target.value; renderRows(filteredEntries()); });
$('#refresh-button').addEventListener('click', () => refresh({ manual: true }));
$('#export-button').addEventListener('click', exportCsv);
function setActiveNav(hash) {
  document.querySelectorAll('.sidebar .nav-item').forEach((link) => {
    const active = link.getAttribute('href') === hash;
    link.classList.toggle('active', active);
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
}
document.querySelectorAll('.sidebar .nav-item').forEach((link) => link.addEventListener('click', () => setActiveNav(link.getAttribute('href'))));
window.addEventListener('hashchange', () => setActiveNav(window.location.hash || '#about'));
setActiveNav(window.location.hash || '#about');
$('#ransomware-shortcut').addEventListener('click', () => { state.onlyRansomware = !state.onlyRansomware; $('#ransomware-shortcut').textContent = state.onlyRansomware ? 'Clear filter ↗' : 'View entries ↗'; render(); document.querySelector('.feed-panel').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
$('#vulnerability-rows').addEventListener('click', (event) => { const button = event.target.closest('.row-detail'); if (button) window.open(`https://www.cve.org/CVERecord?id=${encodeURIComponent(button.dataset.cve)}`, '_blank', 'noopener,noreferrer'); });
document.addEventListener('keydown', (event) => { if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); $('#search-input').focus(); } });
tickClock(); setInterval(tickClock, 1000);
const saved = loadCache();
if (saved) {
  state.catalog = saved.catalog; state.entries = saved.catalog.vulnerabilities; state.cachedAt = saved.savedAt;
  setConnection(false, `Cached · saved ${ageLabel(saved.savedAt)}`); render();
}
refresh(); state.timer = setInterval(() => refresh(), REFRESH_MS);
