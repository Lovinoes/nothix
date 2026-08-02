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

/* Live data on server page: stat tiles + canvas charts, one poll feeds both.
   netin/netout are cumulative Proxmox byte counters — rate = delta / seconds. */
var live = document.querySelector('[data-live-id]');
if (live) {
  var fmtBytes = function (b) {
    if (b >= 1073741824) return (b / 1073741824).toFixed(2) + ' GiB';
    if (b >= 1048576) return (b / 1048576).toFixed(1) + ' MiB';
    if (b >= 1024) return (b / 1024).toFixed(1) + ' KiB';
    return b.toFixed(0) + ' B';
  };
  var fmtRate = function (b) { return fmtBytes(b) + '/s'; };
  var fmtPct = function (v) { return v.toFixed(1) + '%'; };
  var chartEl = function (k) { return live.querySelector('[data-chart=' + k + ']'); };
  var cpuPush = chartEl('cpu') && makeChart(chartEl('cpu'), [{ color: '#3ddc84', data: [] }], fmtPct);
  var memPush = chartEl('mem') && makeChart(chartEl('mem'), [{ color: '#3ddc84', data: [] }], fmtBytes);
  var netPush = chartEl('net') && makeChart(chartEl('net'), [{ color: '#3ddc84', data: [] }, { color: '#a3a3a3', data: [] }], fmtRate);
  var nodePush = null; /* created when the API actually sends nodecpu */
  var prev = null, prevT = 0;
  var fill = function () {
    fetch('/api/server/' + encodeURIComponent(live.getAttribute('data-live-id')) + '/live')
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (!d) return;
        var f = function (k, v) {
          var el = live.querySelector('[data-live=' + k + ']');
          if (el) el.textContent = v;
        };
        f('cpu', fmtPct(d.cpu * 100));
        f('mem', fmtBytes(d.mem));
        if (cpuPush) cpuPush([d.cpu * 100]);
        if (memPush) memPush([d.mem]);
        var now = Date.now();
        if (prev && d.netin >= prev.netin) {
          var dt = (now - prevT) / 1000;
          var inR = (d.netin - prev.netin) / dt;
          var outR = Math.max(0, d.netout - prev.netout) / dt;
          f('netin', fmtRate(inR));
          f('netout', fmtRate(outR));
          if (netPush) netPush([inR, outR]);
        }
        prev = d; prevT = now;
        if (d.nodecpu != null) {
          if (!nodePush && chartEl('nodecpu')) {
            live.querySelectorAll('[data-node]').forEach(function (el) { el.hidden = false; });
            nodePush = makeChart(chartEl('nodecpu'), [{ color: '#3ddc84', data: [] }], fmtPct);
          }
          f('nodecpu', fmtPct(d.nodecpu * 100));
          if (nodePush) nodePush([d.nodecpu * 100]);
        }
      })
      .catch(function () {});
  };
  fill();
  /* livedata endpoint is rate-limited to 30 req / 15 min — poll gently.
     No websocket: the official one (wss://livedata.datalix.de) authenticates
     with the datalix.de session cookie, which an API-key login never has. */
  setInterval(fill, 60000);
}

/* Top up credit: payment modal (credit page) */
var payDlg = document.getElementById('pay-modal');
if (payDlg) {
  var payCountry = document.getElementById('pay-country');
  var payAmount = document.getElementById('pay-amount');

  var payRefresh = function () {
    var opt = payCountry && payCountry.options[payCountry.selectedIndex];
    var vat = opt ? parseFloat(opt.getAttribute('data-vat')) || 0 : 0;
    var eea = opt ? opt.getAttribute('data-ewr') === '1' : true;
    document.getElementById('norefund-eea').hidden = !eea;
    document.getElementById('norefund-noneea').hidden = eea;
    var amt = parseFloat(payAmount.value);
    if (isNaN(amt) || amt < 1) return;
    document.getElementById('pay-euro').textContent = amt.toFixed(2);
    document.getElementById('pay-tax').textContent = (amt / (vat + 100) * vat).toFixed(2);
    document.getElementById('pay-vat').textContent = vat;
  };

  var payOpen = function (card) {
    document.getElementById('pay-name').textContent = card.getAttribute('data-name');
    document.getElementById('pay-modal-logo').src = card.getAttribute('data-logo');
    document.getElementById('pay-crypto-note').hidden = card.getAttribute('data-crypto') !== '1';
    document.querySelectorAll('.pay-method-input').forEach(function (i) {
      i.value = card.getAttribute('data-method');
    });
    payRefresh();
    payDlg.showModal();
  };

  document.querySelectorAll('.pay-card').forEach(function (c) {
    c.addEventListener('click', function () { payOpen(c); });
  });

  payAmount.addEventListener('input', payRefresh);
  if (payCountry) payCountry.addEventListener('change', payRefresh);

  /* re-open the modal after an invoice data save round-trip */
  var reopen = payDlg.getAttribute('data-open');
  if (reopen) {
    var card = document.querySelector('.pay-card[data-method="' + reopen + '"]');
    if (card) payOpen(card);
  }
}

/* Modals: every .modal dialog gets close buttons + backdrop-click once;
   [data-dlg] buttons open the dialog named in the attribute and prefill
   its fields from their own data-* attributes. */
document.querySelectorAll('dialog.modal').forEach(function (dlg) {
  dlg.querySelectorAll('[data-close]').forEach(function (c) {
    c.addEventListener('click', function () { dlg.close(); });
  });
  dlg.addEventListener('click', function (e) { if (e.target === dlg) dlg.close(); });
});
document.querySelectorAll('[data-dlg]').forEach(function (b) {
  b.addEventListener('click', function (e) {
    e.preventDefault(); // openers may be <a> fallback-links (no-JS goes to href)
    var ext = b.getAttribute('data-ext');
    if (ext) {
      var l = document.getElementById('ext-link');
      if (l) l.href = ext;
    }
    var d = document.getElementById(b.getAttribute('data-dlg'));
    if (!d) return;
    Object.keys(b.dataset).forEach(function (k) {
      if (k === 'dlg' || k === 'ext') return;
      var f = d.querySelector('[name=' + k + ']');
      if (f) f.value = b.dataset[k];
    });
    d.showModal();
  });
});

/* Live tab: tiny canvas line charts fed by the same 60 s polling */
function makeChart(canvas, series, fmt) {
  var ctx = canvas.getContext('2d');
  function draw() {
    var dpr = window.devicePixelRatio || 1;
    var w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    var maxV = 1;
    series.forEach(function (s) {
      s.data.forEach(function (v) { if (v > maxV) maxV = v; });
    });
    maxV *= 1.15;
    ctx.strokeStyle = 'rgba(255,255,255,0.07)';
    ctx.lineWidth = 1;
    for (var g = 1; g < 4; g++) {
      var gy = h - 6 - (h - 24) * g / 4;
      ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(w, gy); ctx.stroke();
    }
    series.forEach(function (s) {
      var n = s.data.length;
      if (n < 2) return;
      ctx.strokeStyle = s.color;
      ctx.lineWidth = 1.5;
      ctx.lineJoin = 'round';
      ctx.beginPath();
      for (var i = 0; i < n; i++) {
        var x = (i / (n - 1)) * (w - 8) + 4;
        var y = h - 6 - (s.data[i] / maxV) * (h - 24);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      }
      ctx.stroke();
    });
    ctx.fillStyle = 'rgba(255,255,255,0.45)';
    ctx.font = '10px monospace';
    ctx.fillText(fmt(maxV), 6, 12);
  }
  draw();
  return function push(vals) {
    series.forEach(function (s, i) {
      s.data.push(vals[i]);
      if (s.data.length > 180) s.data.shift();
    });
    draw();
  };
}


/* Access page: the create dialog shows the permission set matching the
   selected service; disabled fieldsets keep their boxes out of the POST. */
var accSvc = document.getElementById('access-service');
if (accSvc) {
  var accSync = function () {
    var opt = accSvc.options[accSvc.selectedIndex];
    var pid = opt ? opt.getAttribute('data-pid') : '';
    document.querySelectorAll('#access-create-modal .perm-set').forEach(function (fs) {
      var on = fs.getAttribute('data-pid') === pid;
      fs.hidden = !on;
      fs.disabled = !on;
    });
  };
  accSvc.addEventListener('change', accSync);
  accSync();
}
/* permission trees: checking a sub checks its parent, unchecking a parent
   clears its subs (same behavior as the official panel) */
document.querySelectorAll('.perm-set').forEach(function (fs) {
  fs.addEventListener('change', function (e) {
    var cb = e.target;
    if (cb.type !== 'checkbox') return;
    if (cb.checked && cb.hasAttribute('data-parent')) {
      var p = fs.querySelector('input[value="' + cb.getAttribute('data-parent') + '"]');
      if (p) p.checked = true;
    }
    if (!cb.checked) {
      fs.querySelectorAll('input[data-parent="' + cb.value + '"]').forEach(function (sub) {
        sub.checked = false;
      });
    }
  });
});
