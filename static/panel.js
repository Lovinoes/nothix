/* Datalix Panel — minimal vanilla JS. No frameworks. CSP-safe (no inline). */
'use strict';

/* Confirm dialogs on destructive forms */
document.querySelectorAll('form[data-confirm]').forEach(function (f) {
  f.addEventListener('submit', function (e) {
    if (!window.confirm(f.getAttribute('data-confirm'))) e.preventDefault();
  });
});

/* Clickable table rows (service overview) — clicks on controls still work */
document.querySelectorAll('tr[data-href]').forEach(function (row) {
  row.addEventListener('click', function (e) {
    if (e.target.closest('a, button, form, input, select, label')) return;
    window.location = row.getAttribute('data-href');
  });
});

/* Copy-to-clipboard */
document.querySelectorAll('[data-copy]').forEach(function (btn) {
  btn.addEventListener('click', function () {
    navigator.clipboard.writeText(btn.getAttribute('data-copy')).then(function () {
      var old = btn.textContent;
      btn.textContent = 'copied';
      setTimeout(function () { btn.textContent = old; }, 1200);
    });
  });
});

/* Lazy status badges: <span class="status" data-status-id="UUID"> */
var STATUS_DOWN = ['stopped', 'offline', 'stopping', 'down', 'maintenance', 'overusage'];
function setStatus(el, s) {
  el.classList.remove('running', 'stopped', 'pending');
  var cls = 'pending';
  if (s === 'running') cls = 'running';
  else if (STATUS_DOWN.indexOf(s) !== -1) cls = 'stopped';
  el.classList.add(cls);
  el.textContent = s;
}
document.querySelectorAll('[data-status-id]').forEach(function (el) {
  fetch('/api/server/' + encodeURIComponent(el.getAttribute('data-status-id')) + '/status')
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) { if (d && d.status) setStatus(el, d.status); })
    .catch(function () {});
});

/* Live data on server page: container with data-live-id, children [data-live=cpu|mem|netin|netout] */
var live = document.querySelector('[data-live-id]');
if (live) {
  var fill = function () {
    fetch('/api/server/' + encodeURIComponent(live.getAttribute('data-live-id')) + '/live')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        var f = function (k, v) {
          var el = live.querySelector('[data-live=' + k + ']');
          if (el) el.textContent = v;
        };
        f('cpu', (d.cpu * 100).toFixed(1) + '%');
        f('mem', (d.mem / 1073741824).toFixed(2) + ' GiB');
        f('netin', (d.netin / 1048576).toFixed(1) + ' MiB/s');
        f('netout', (d.netout / 1048576).toFixed(1) + ' MiB/s');
      })
      .catch(function () {});
  };
  fill();
  /* livedata endpoint is rate-limited to 30 req / 15 min — poll gently */
  setInterval(fill, 60000);
}
