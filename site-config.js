// Trade coin site settings API. In server.js add, after `app` is created and express.json() is set up:
//   require('./site-config')(app);
// Stores the settings in site.json next to the database file. Only admin tokens can change them.
const fs = require('fs'), path = require('path'), jwt = require('jsonwebtoken');
const FILE = path.join(path.dirname(process.env.DB_PATH || path.join(__dirname, 'wallet.db')), 'site.json');
module.exports = (app) => {
  const read = () => { try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch (e) { return { layout: 1 }; } };
  app.get('/site/config', (req, res) => { res.set('Cache-Control', 'no-store'); res.json(read()); });
  app.put('/admin/site', require('express').json({ limit: '100kb' }), (req, res) => {
    try {
      const p = jwt.verify((req.headers.authorization || '').replace(/^Bearer /, ''), process.env.JWT_SECRET);
      if (p.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    } catch (e) { return res.status(401).json({ error: 'Please log in again' }); }
    const b = req.body || {}, l = parseInt(b.layout, 10), vars = {};
    for (const k in (b.vars || {})) if (/^[a-z-]{1,20}$/.test(k) && /^#[0-9a-f]{6}$/i.test(b.vars[k])) vars[k] = b.vars[k];
    const c = { layout: l >= 1 && l <= 10 ? l : 1, title: String(b.title || '').slice(0, 80), vars, css: String(b.css || '').slice(0, 20000),
      texts: (Array.isArray(b.texts) ? b.texts : []).slice(0, 60).map((r) => ({ sel: String(r.sel || '').slice(0, 120), text: String(r.text || '').slice(0, 500) })),
      hideTabs: (Array.isArray(b.hideTabs) ? b.hideTabs : []).slice(0, 10).map((x) => String(x).slice(0, 20)) };
    fs.writeFileSync(FILE, JSON.stringify(c)); res.json(c);
  });
};
