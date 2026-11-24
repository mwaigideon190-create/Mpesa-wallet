// Run once in your project folder (where server.js is):  node patch-server.js
// Makes a backup (server.js.bak), then applies the 2 edits needed for the Trade coin Site editor. Safe to run twice.
const fs = require('fs');
if (!fs.existsSync('server.js')) { console.log('server.js not found here. Run this in the folder that contains server.js.'); process.exit(1); }
let s = fs.readFileSync('server.js', 'utf8'); const orig = s;
if (!fs.existsSync('server.js.bak')) fs.writeFileSync('server.js.bak', orig);
const done = [];
if (s.includes("express.json({ limit: '20kb' })")) { s = s.replace("express.json({ limit: '20kb' })", "express.json({ limit: '100kb' })"); done.push('JSON limit raised to 100kb'); }
const line = "require('./site-config')({ app, auth, adminOnly, wrap, DB_FILE });";
if (!s.includes("require('./site-config')")) {
  const i = s.lastIndexOf('app.listen(');
  if (i < 0) { console.log('Could not find app.listen( in server.js. Add this line above it by hand:\n' + line); process.exit(1); }
  s = s.slice(0, i) + '// Trade coin site editor (layouts, text edits)\n' + line + '\n\n' + s.slice(i); done.push('site editor connected');
}
if (s !== orig) fs.writeFileSync('server.js', s);
console.log(done.length ? 'Done: ' + done.join('; ') + '. Backup: server.js.bak' : 'Nothing to change: server.js is already patched.');
