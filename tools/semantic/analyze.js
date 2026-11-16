// Compile-check KQL with Microsoft's own Kusto language service (offline, no cluster).
// stdin : JSON [{"name": "...", "text": "..."}]
// stdout: JSON [{"name": "...", "errors": [{"line": n, "message": "...", "at": "..."}]}]
const path = require('path');
const fs = require('fs');
const pkg = path.join(__dirname, 'node_modules', '@kusto', 'language-service-next');
require(path.join(pkg, 'bridge.js'));
require(path.join(pkg, 'Kusto.Language.Bridge.js'));
const K = Kusto.Language;

function analyze(text) {
  const diags = K.KustoCode.ParseAndAnalyze(text).GetDiagnostics();
  const n = diags.Count !== undefined ? diags.Count : diags.length;
  const errors = [];
  for (let i = 0; i < n; i++) {
    const d = diags.getItem ? diags.getItem(i) : diags[i];
    if (d.Severity !== 'Error') continue;
    errors.push({
      line: text.slice(0, d.Start).split('\n').length,
      message: d.Message,
      at: text.slice(d.Start, d.Start + Math.min(d.Length, 60)),
    });
  }
  return errors;
}

const items = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(items.map(it => ({ name: it.name, errors: analyze(it.text) }))));
