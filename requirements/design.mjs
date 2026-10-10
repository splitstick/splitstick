// Validate the design layer and emit the design traceability matrix.
import fs from 'node:fs';

const reqs = [...JSON.parse(fs.readFileSync('requirements/backlog.json','utf8')).requirements,
  ...['part2','part3','part4'].flatMap(p => JSON.parse(fs.readFileSync(`requirements/${p}.json`,'utf8')))];
const byId = new Map(reqs.map(r => [r.id, r]));
const { note, elements, nondesign } = JSON.parse(fs.readFileSync('requirements/design.json','utf8'));
const { milestones } = JSON.parse(fs.readFileSync('requirements/milestones.json','utf8'));
const msOf = new Map(); for (const m of milestones) for (const id of m.ids) msOf.set(id, m.id);
const r10 = new Set(reqs.filter(r => r.release === '1.0').map(r => r.id));

const errs = [], covered = new Map(), classed = new Map();
for (const e of elements) for (const id of e.covers) {
  if (!byId.has(id)) errs.push(`${e.id}: covers unknown requirement ${id}`);
  covered.set(id, (covered.get(id) || []).concat(e.id));
}
for (const [k, ids] of Object.entries(nondesign)) for (const id of ids) {
  if (!byId.has(id)) errs.push(`nondesign.${k}: unknown requirement ${id}`);
  if (classed.has(id)) errs.push(`${id}: classified in two non-design buckets`);
  classed.set(id, k);
}
for (const id of r10) {
  if (!covered.has(id) && !classed.has(id)) errs.push(`${id}: neither traced to a design element nor classified non-design`);
  if (covered.has(id) && classed.has(id)) errs.push(`${id}: both traced to a design element and classified non-design`);
}
// a design element must not depend on a requirement from a later milestone than its own
const order = JSON.parse(fs.readFileSync('requirements/depends.json','utf8')).order;
for (const e of elements) for (const id of e.covers) {
  if (!msOf.has(id)) continue;
  if (order.indexOf(msOf.get(id)) < order.indexOf(e.milestone))
    errs.push(`${e.id} (${e.milestone}) covers ${id}, which is due earlier in ${msOf.get(id)}`);
}
if (errs.length) { console.error('DESIGN VALIDATION FAILED:\n' + errs.join('\n')); process.exit(1); }

const esc = s => String(s).replace(/\|/g,'\\|');
let md = `# Design traceability matrix

${note}

**Generated — do not edit by hand.** Source of truth is \`requirements/design.json\`.
Regenerate with \`npm run backlog\`.

## Totals

| | Count |
|---|---:|
| Design elements | ${elements.length} |
| Release-1.0 requirements traced to a design element | ${[...r10].filter(i=>covered.has(i)).length} |
| Classified non-design | ${[...r10].filter(i=>classed.has(i)).length} |
| **Total 1.0** | **${r10.size}** |

### Non-design classifications

| Kind | Count | Meaning |
|---|---:|---|
| policy | ${nondesign.policy.length} | a stated rule and a recurring audit, with nothing to build |
| document | ${nondesign.document.length} | prose that must exist and be accurate |
| process | ${nondesign.process.length} | a repeatable procedure, often enforced in CI |
| audit | ${nondesign.audit.length} | a check performed against the project itself |

## Design elements

`;
for (const e of elements) {
  md += `### ${e.id} — ${e.title}\n\n`;
  md += `**Milestone:** ${e.milestone} · **Requirements covered:** ${e.covers.length}\n\n`;
  md += `${e.decides}\n\n`;
  md += `| Requirement | | Status |\n|---|---|---|\n`;
  for (const id of e.covers) {
    const r = byId.get(id);
    md += `| \`${id}\` | ${esc(r.title)} | ${r.status === 'done' ? '✅' : '☐'} |\n`;
  }
  md += `\n`;
}
md += `## Requirements with no design element\n\nDeliberate, not an oversight. Each is a rule, a document, a procedure or a check.\n\n`;
for (const [k, ids] of Object.entries(nondesign)) {
  md += `### ${k} — ${ids.length}\n\n`;
  md += ids.map(id => `- \`${id}\` ${byId.get(id).title}`).join('\n') + '\n\n';
}
fs.writeFileSync('requirements/DESIGN.md', md);
console.log(`design validated: ${elements.length} elements, ${covered.size} requirements traced, ${classed.size} classified, 0 errors`);
for (const e of elements) console.log(`  ${e.id}  ${e.milestone.padEnd(4)} ${String(e.covers.length).padStart(2)} reqs  ${e.title}`);
