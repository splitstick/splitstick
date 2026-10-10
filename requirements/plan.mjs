// Sequence the 1.0 backlog into milestones gated by attack class.
import fs from 'node:fs';

const base = JSON.parse(fs.readFileSync('requirements/backlog.json','utf8'));
const extra = ['requirements/part2.json','requirements/part3.json','requirements/part4.json']
  .flatMap(f => JSON.parse(fs.readFileSync(f,'utf8')));
const reqs = [...base.requirements, ...extra];
const byId = new Map(reqs.map(r => [r.id, r]));
const { gates, milestones, regressionRule } = JSON.parse(fs.readFileSync('requirements/milestones.json','utf8'));
const { order, depends } = JSON.parse(fs.readFileSync('requirements/depends.json','utf8'));

// --- validate ---------------------------------------------------------------
const errs = [], assigned = new Map();
for (const m of milestones) {
  const dup = m.ids.filter((id, i) => m.ids.indexOf(id) !== i);
  if (dup.length) errs.push(`${m.id}: duplicate ids in list: ${[...new Set(dup)].join(' ')}`);
}
for (const m of milestones) for (const id of m.ids) {
  if (!byId.has(id)) errs.push(`${m.id}: unknown id ${id}`);
  if (assigned.has(id)) errs.push(`${id}: assigned to both ${assigned.get(id)} and ${m.id}`);
  assigned.set(id, m.id);
}
const r10 = reqs.filter(r => r.release === '1.0');
for (const r of r10) if (!assigned.has(r.id)) errs.push(`${r.id}: unassigned (release 1.0)`);
for (const m of milestones) for (const g of m.gate) if (!gates[g]) errs.push(`${m.id}: unknown gate ${g}`);
const gated = new Set(milestones.flatMap(m => m.gate));
for (const g of Object.keys(gates)) if (!gated.has(g)) errs.push(`gate ${g}: never closed by any milestone`);
// ordering: a requirement may not depend on one in a later milestone
const msOfId = new Map();
for (const m of milestones) for (const id of m.ids) msOfId.set(id, m.id);
const pos = id => order.indexOf(msOfId.get(id));
for (const [id, deps] of Object.entries(depends)) {
  if (!msOfId.has(id)) continue;
  for (const dep of deps) {
    if (!msOfId.has(dep)) { errs.push(`${id}: depends on ${dep}, which is in no 1.0 milestone`); continue; }
    if (pos(dep) > pos(id)) errs.push(`${id} (${msOfId.get(id)}) depends on ${dep} (${msOfId.get(dep)}) — later milestone`);
  }
}
// dependency cycles: milestone ordering alone cannot catch a same-milestone cycle
const seenCycles = new Set();
const visit = (n, path) => {
  if (path.includes(n)) {
    const cyc = [...path.slice(path.indexOf(n)), n].join(' -> ');
    if (!seenCycles.has(cyc)) { seenCycles.add(cyc); errs.push(`dependency cycle: ${cyc}`); }
    return;
  }
  for (const m of depends[n] || []) visit(m, [...path, n]);
};
for (const n of Object.keys(depends)) visit(n, []);
if (errs.length) { console.error('PLAN VALIDATION FAILED:\n' + errs.join('\n')); process.exit(1); }

// --- emit -------------------------------------------------------------------
const esc = s => String(s).replace(/\|/g,'\\|');
const typeOf = id => byId.get(id).type;
const TY = {functional:'FR','non-functional':'NFR',security:'SEC',privacy:'PRIV',legal:'LEG',
  governance:'GOV',operational:'OPS',interoperability:'INT','scope-guard':'SCOPE',
  documentation:'DOC',roadmap:'RM',traceability:'TRC'};

let md = `# Delivery plan — Splitstick 1.0

${r10.length} release-1.0 requirements sequenced into ${milestones.length} milestones, gated by the attack-class
table in [the release notes](../docs/splitstick-1.0-release-notes.md).

**Generated — do not edit by hand.** Source of truth is \`requirements/milestones.json\`.
Regenerate with \`npm run plan\`.

The rule: **no milestone is complete until its attack classes fail closed against our own
verifier.** Not a code review, not a demo — the red-team suite, with that class's expectation
flipped from \`undetected\` to \`detected\`.

${regressionRule}

## Attack-class gates

| Gate | Class | Closed by | Red-team |
|---|---|---|---|
${Object.entries(gates).map(([g,v]) => {
  const m = milestones.find(m => m.gate.includes(g));
  return `| \`${g}\` | ${esc(v.class)} | ${m.id} ${m.name} | ${v.redteam} (${v.kind}) |`;
}).join('\n')}

## Sequence

| Milestone | Gate | Reqs | Weeks | Goal |
|---|---|---:|---|---|
${milestones.map(m => `| **${m.id}** ${esc(m.name)} | ${m.gate.length ? m.gate.join(', ') : '—'} | ${m.ids.length} | ${m.weeks} | ${esc(m.goal)} |`).join('\n')}
| | | **${milestones.reduce((a,m)=>a+m.ids.length,0)}** | | |

## Milestones
`;

for (const m of milestones) {
  const mix = Object.entries(m.ids.reduce((a,id)=>(a[TY[typeOf(id)]]=(a[TY[typeOf(id)]]||0)+1,a),{}))
    .sort((a,b)=>b[1]-a[1]).map(([k,v])=>`${k}×${v}`).join('  ');
  md += `\n### ${m.id} — ${m.name}\n\n`;
  md += `${m.goal}\n\n`;
  md += `- **Gate:** ${m.gate.length ? m.gate.map(g=>`\`${g}\` — ${gates[g].class}`).join('; ') : 'none — unlocks adoption rather than closing an attack class'}\n`;
  md += `- **Requirements:** ${m.ids.length} (${mix})\n`;
  md += `- **Effort:** weeks ${m.weeks}\n`;
  md += `- **Exit criteria:** ${m.exit}\n\n`;
  md += `| | ID | Requirement | Verified by |\n|---|---|---|---|\n`;
  for (const id of m.ids) {
    const r = byId.get(id);
    md += `| ${r.status==='done'?'✅':'☐'} \`${id}\` | **${esc(r.title)}** — ${esc(r.statement)} | ${esc(r.verify)} |\n`;
  }
}

md += `\n## Deferred\n\n`;
for (const rel of ['2.0','commercial']) {
  const rows = reqs.filter(r => r.release === rel);
  md += `\n**${rel} — ${rows.length}**\n\n`;
  md += rows.map(r => `- \`${r.id}\` ${r.title}`).join('\n') + '\n';
}
md += `\n---\n\n*${r10.length} requirements in 1.0 across ${milestones.length} milestones; ${reqs.length} total in the backlog.*\n`;

fs.writeFileSync('requirements/PLAN.md', md);

console.log(`plan validated: ${r10.length} requirements, ${milestones.length} milestones, all 7 gates closed, ${Object.keys(depends).length} ordering constraints, 0 errors\n`);
for (const m of milestones) {
  const g = m.gate.length ? m.gate.join(',') : '—';
  const openN = m.ids.filter(id=>byId.get(id).status!=='done').length;
  console.log(`  ${m.id.padEnd(4)} ${m.name.padEnd(32)} ${String(openN).padStart(3)} open / ${String(m.ids.length).padStart(3)}   gate ${g.padEnd(11)} wk ${m.weeks}`);
}
console.log(`\n  ${'TOTAL'.padEnd(30)} ${String(milestones.reduce((a,m)=>a+m.ids.length,0)).padStart(3)} reqs`);
