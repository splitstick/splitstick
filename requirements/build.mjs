// Merge the backlog parts, validate traceability, emit the matrix.
import fs from 'node:fs';

const base = JSON.parse(fs.readFileSync('requirements/backlog.json','utf8'));
const plan = JSON.parse(fs.readFileSync('requirements/milestones.json','utf8'));
const msOf = new Map();
for (const m of plan.milestones) for (const id of m.ids) msOf.set(id, m.id);
const extra = ['requirements/part2.json','requirements/part3.json','requirements/part4.json']
  .flatMap(f => JSON.parse(fs.readFileSync(f,'utf8')));
const reqs = [...base.requirements, ...extra];

// --- validate ---------------------------------------------------------------
const errs = [];
const seen = new Set();
for (const r of reqs) {
  for (const k of ['id','type','release','title','statement','source','verify']) {
    if (!r[k] || !String(r[k]).trim()) errs.push(`${r.id ?? '??'}: missing ${k}`);
  }
  if (seen.has(r.id)) errs.push(`${r.id}: duplicate id`);
  seen.add(r.id);
}
if (errs.length) { console.error('VALIDATION FAILED:\n' + errs.join('\n')); process.exit(1); }

// --- counts -----------------------------------------------------------------
const by = (k) => reqs.reduce((a,r) => (a[r[k]] = (a[r[k]]||0)+1, a), {});
const types = by('type'), rels = by('release');

const TYPE_LABEL = {
  functional:'Functional', 'non-functional':'Non-functional', security:'Security',
  privacy:'Privacy & data protection', legal:'Legal & regulatory',
  governance:'Governance, licensing & community', operational:'Operational',
  interoperability:'Interoperability & standards', 'scope-guard':'Scope guards (negative)',
  documentation:'Documentation & transparency', roadmap:'Roadmap (post-1.0)',
  traceability:'Traceability & process',
};

// --- emit matrix ------------------------------------------------------------
const esc = (s) => String(s).replace(/\|/g,'\\|');
let md = `# Requirements traceability matrix

Derived line by line from [${base.source}](../docs/tally-1.0-release-notes.md).

${base.note}

**Generated — do not edit by hand.** Source of truth is \`requirements/*.json\`.
Regenerate with \`npm run requirements\`.

## Totals

| Category | Count |
|---|---:|
${Object.entries(types).sort((a,b)=>b[1]-a[1]).map(([t,c])=>`| ${TYPE_LABEL[t]??t} | ${c} |`).join('\n')}
| **Total** | **${reqs.length}** |

### By release

| Release | Count |
|---|---:|
${Object.entries(rels).sort().map(([t,c])=>`| ${t} | ${c} |`).join('\n')}
| **Total** | **${reqs.length}** |

## Matrix
`;

for (const [t,label] of Object.entries(TYPE_LABEL)) {
  const rows = reqs.filter(r => r.type === t);
  if (!rows.length) continue;
  md += `\n### ${label} — ${rows.length}\n\n`;
  md += `| ID | Requirement | Traces to | Verified by | Rel | M | Status |\n|---|---|---|---|---|---|---|\n`;
  for (const r of rows) {
    md += `| \`${r.id}\` | **${esc(r.title)}** — ${esc(r.statement)} | ${esc(r.source)} | ${esc(r.verify)} | ${r.release} | ${msOf.get(r.id) ?? '—'} | ☐ |\n`;
  }
}
md += `\n---\n\n*${reqs.length} requirements. Status column is maintained by hand as work lands.*\n`;

fs.writeFileSync('requirements/MATRIX.md', md);
fs.writeFileSync('requirements/backlog.resolved.json', JSON.stringify({source:base.source, count:reqs.length, requirements:reqs}, null, 2));

console.log(`validated ${reqs.length} requirements, 0 errors\n`);
const w = Math.max(...Object.values(TYPE_LABEL).map(s=>s.length));
for (const [t,c] of Object.entries(types).sort((a,b)=>b[1]-a[1]))
  console.log(`  ${(TYPE_LABEL[t]??t).padEnd(w)}  ${String(c).padStart(3)}`);
console.log(`  ${'—'.repeat(w)}  ---`);
console.log(`  ${'TOTAL'.padEnd(w)}  ${String(reqs.length).padStart(3)}`);
console.log(`\n  by release: ${Object.entries(rels).sort().map(([k,v])=>`${k}=${v}`).join('  ')}`);
