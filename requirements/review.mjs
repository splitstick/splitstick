// Mechanical review of the requirement and design set. Structural checks only —
// substance still needs a reader.
import fs from 'node:fs';

const reqs = [...JSON.parse(fs.readFileSync('requirements/backlog.json','utf8')).requirements,
  ...['part2','part3','part4'].flatMap(p => JSON.parse(fs.readFileSync(`requirements/${p}.json`,'utf8')))];
const byId = new Map(reqs.map(r => [r.id, r]));
const { elements, nondesign } = JSON.parse(fs.readFileSync('requirements/design.json','utf8'));
const specs = new Map(elements.map(e => [e.id, fs.readFileSync(e.spec,'utf8')]));
const ownedBy = new Map(); for (const e of elements) for (const id of e.covers) ownedBy.set(id, e.id);
const classified = new Set(Object.values(nondesign).flat());
const ID = /\b(FR|NFR|SEC|PRIV|LEG|GOV|OPS|INT|SCOPE|DOC|TRC|RM)-\d+\b/g;

const out = []; const flag = (k, m) => out.push(`${k}  ${m}`);

// 1. a spec must mention, by id, every requirement it claims to cover
for (const e of elements) {
  const miss = e.covers.filter(id => !specs.get(e.id).includes(id));
  if (miss.length) flag('TRACE ', `${e.id} covers but never names: ${miss.join(' ')}`);
}

// 2. a spec must not cite an unknown id, or a 1.0 requirement nothing owns
for (const e of elements) for (const id of new Set(specs.get(e.id).match(ID) || [])) {
  if (!byId.has(id)) { flag('BADREF', `${e.id} cites unknown ${id}`); continue; }
  if (byId.get(id).release !== '1.0') continue;              // deferred ids are checked below
  if (!ownedBy.has(id) && !classified.has(id))
    flag('ORPHAN', `${e.id} cites ${id}, which no element owns and nothing classifies`);
}

// 3. a deferred requirement cited in a spec must be marked as deferred on that line
for (const e of elements) for (const id of new Set(specs.get(e.id).match(ID) || [])) {
  const r = byId.get(id); if (!r || r.release === '1.0') continue;
  const line = specs.get(e.id).split('\n').find(l => l.includes(id)) || '';
  if (!/2\.0|funded|deferred|commercial|later|RM-/.test(line))
    flag('LEAK  ', `${e.id} cites ${id} (${r.release}) without marking it deferred`);
}

// 4. the specs must not themselves break the scope guards
const BANNED = [/tamper[- ]proof/i, /\bcertified\b/i, /\bcompliance certificate\b/i, /\bguarantees? compliance\b/i];
for (const [id, s] of specs) for (const line of s.split('\n')) for (const re of BANNED)
  if (re.test(line) && !/not |never |no |cannot |does not |is not /i.test(line))
    flag('CLAIM ', `${id}: "${line.trim().slice(0,90)}"`);

// 5. dangling design references
for (const [id, s] of specs) for (const d of new Set(s.match(/\bDES-\d+\b/g) || []))
  if (!elements.some(e => e.id === d)) flag('BADREF', `${id} references nonexistent ${d}`);

// 6. a requirement we BUILD should be verifiable without a human reading something.
//    Policy, document, process and audit requirements are human-verified by definition.
const HUMAN = /review|inspection|published|documented|present|inventory|audit(?!able)/i;
const AUTO  = /test|benchmark|red-team|fails closed|verifies|detected|captur|scan|drill|e2e|ci\b/i;
for (const r of reqs.filter(r => r.release === '1.0' && ownedBy.has(r.id)))
  if (HUMAN.test(r.verify) && !AUTO.test(r.verify))
    flag('MANUAL', `${r.id} (${ownedBy.get(r.id)}) is built but verified by human review: "${r.verify}"`);

// 7. prose must not restate counts or retracted figures — both drifted in review
const PROSE = ['README.md','docs/splitstick-1.0-release-notes.md','docs/threat-model.md'];
const STALE = [
  [/\b\d{2,3} (?:requirements|design elements)\b/, 'a hardcoded count in prose; counts belong in the generated matrices'],
  [/EUR 5,000|EUR 50,000/, 'a cash bounty figure retracted when the award became recognition'],
  [/\bexternal arbiter\b/, 'the arbiter requirement was removed when adjudication was removed'],
  [/shipped default is .\[rekor\]/, 'the default became a TSA plus a roll-up anchor; a transparency log is opt-in'],
  [/100% of tool calls captured/, 'coverage reports what the collector reported, not what occurred'],
  [/Either way it is attributable/, 'patching a collector is not detectable; only stopping it is'],
  [/time lower bound/, 'OpenTimestamps establishes existed-no-later-than, not a lower bound'],
  [/immediate successor of the previous/, 'a witness verifies a consistency proof, not an increment of one'],
];
for (const f of PROSE) {
  if (!fs.existsSync(f)) continue;
  const lines = fs.readFileSync(f,'utf8').split('\n');
  lines.forEach((l, i) => { for (const [re, why] of STALE)
    if (re.test(l) && !/never in prose|retracted|removed when|generated matri|^\|\s*\d+\s*\|/.test(l))
      flag('STALE ', `${f}:${i+1} ${why} -> "${l.trim().slice(0,70)}"`); });
}

console.log(out.length ? out.map(l => '  ' + l).join('\n') : '  no structural issues');
console.log(`\n  ${out.length} finding(s) across ${reqs.length} requirements and ${elements.length} design elements`);
