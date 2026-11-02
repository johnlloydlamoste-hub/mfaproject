const $ = (s) => document.querySelector(s);
const H = { 'X-Requested-With': 'fetch' };

async function api(url, opts = {}) {
  const r = await fetch(url, { ...opts, headers: { ...H, ...(opts.headers || {}) } });
  if (r.status === 401) { location.reload(); throw new Error('Signed out'); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || 'Request failed');
  return data;
}
function status(msg, err) { const s = $('#status'); s.textContent = msg; s.className = 'status' + (err ? ' err' : ''); }

function render(images) {
  const grid = $('#grid'); grid.replaceChildren();
  $('#empty').hidden = images.length > 0;
  for (const img of images) {
    const tile = document.createElement('div'); tile.className = 'tile';
    const a = document.createElement('a'); a.href = '/api/images/' + img.id; a.target = '_blank'; a.rel = 'noopener';
    const el = document.createElement('img'); el.src = a.href; el.alt = img.name; el.title = img.name; el.loading = 'lazy';
    a.append(el);
    const del = document.createElement('button'); del.className = 'del'; del.textContent = '×';
    del.setAttribute('aria-label', 'Delete ' + img.name);
    del.onclick = async () => {
      if (!confirm('Delete "' + img.name + '"?')) return;
      try { await api('/api/images/' + img.id, { method: 'DELETE' }); load(); } catch (e) { status(e.message, true); }
    };
    tile.append(a, del); grid.append(tile);
  }
}
async function load() { render((await api('/api/images')).images); }

async function upload(files) {
  let ok = 0, bad = [];
  for (const f of files) {
    status(`Uploading ${f.name}…`);
    try {
      await api('/api/images', { method: 'POST', body: f, headers: { 'Content-Type': 'application/octet-stream', 'X-Filename': encodeURIComponent(f.name) } });
      ok++;
    } catch (e) { bad.push(`${f.name}: ${e.message}`); }
  }
  await load();
  status(bad.length ? bad.join(' · ') : `Uploaded ${ok} image${ok === 1 ? '' : 's'}.`, bad.length > 0);
}

const drop = $('#drop'), file = $('#file');
drop.onclick = () => file.click();
drop.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); file.click(); } };
file.onchange = () => { if (file.files.length) upload([...file.files]); file.value = ''; };
for (const ev of ['dragenter', 'dragover']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); });
for (const ev of ['dragleave', 'drop']) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove('over'); });
drop.addEventListener('drop', (e) => { if (e.dataTransfer.files.length) upload([...e.dataTransfer.files]); });

$('#logout').onclick = async () => {
  try { await fetch('/api/logout', { method: 'POST', headers: H }); } finally { location.reload(); }
};
load().catch((e) => status(e.message, true));
