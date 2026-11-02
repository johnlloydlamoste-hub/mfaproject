const $ = (s) => document.querySelector(s);
let mode = 'in';

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
    body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(data.error || 'Something went wrong'), data);
  return data;
}
function show(id) {
  for (const s of ['creds', 'setup', 'mfa']) $('#' + s).hidden = s !== id;
  const input = $('#' + id + ' input');
  if (input) input.focus();
}
function setMode(m) {
  mode = m;
  $('#tab-in').setAttribute('aria-selected', m === 'in');
  $('#tab-up').setAttribute('aria-selected', m === 'up');
  $('#p').autocomplete = m === 'in' ? 'current-password' : 'new-password';
  $('#e1').textContent = '';
}
$('#tab-in').onclick = () => setMode('in');
$('#tab-up').onclick = () => setMode('up');

function showSetup({ secret, uri }) {
  $('#secret').textContent = secret.match(/.{1,4}/g).join(' ');
  const img = $('#qr');
  img.hidden = true;
  try { // QR is a convenience; manual key above always works
    const qr = qrcode(0, 'M'); qr.addData(uri); qr.make();
    img.src = qr.createDataURL(5); img.hidden = false;
  } catch { /* library unavailable → manual entry */ }
  show('setup');
}

$('#credsForm').onsubmit = async (e) => {
  e.preventDefault();
  const btn = $('#go1'); btn.disabled = true; $('#e1').textContent = '';
  try {
    const d = await post(mode === 'in' ? '/api/login' : '/api/register',
      { username: $('#u').value, password: $('#p').value });
    $('#p').value = '';
    if (d.setup) showSetup(d); else show('mfa');
  } catch (err) { $('#e1').textContent = err.message; }
  btn.disabled = false;
};

async function verify(inputSel, errSel) {
  try {
    await post('/api/mfa', { code: $(inputSel).value });
    location.reload(); // server now serves the folder page
  } catch (err) {
    $(errSel).textContent = err.message;
    $(inputSel).value = '';
    if (err.restart) setTimeout(() => location.reload(), 1500);
  }
}
$('#setupForm').onsubmit = (e) => { e.preventDefault(); verify('#c1', '#e2'); };
$('#mfaForm').onsubmit = (e) => { e.preventDefault(); verify('#c2', '#e3'); };
$('#back').onclick = () => location.reload();
