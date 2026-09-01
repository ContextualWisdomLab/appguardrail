export function parseMsProjectXml(xml) {
  const tag = (block, name) => {
    const m = block.match(new RegExp(`<${name}>([^<]*)</${name}>`));
    return m ? m[1].trim() : '';
  };
  const unescape = (s) => s
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '\"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  const day = (s) => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : '');
  const tasks = [];
  const parents = {}; // depth -> last task id at that depth
  const blocks = xml.match(/<Task>[\s\S]*?<\/Task>/g) || [];
  for (const block of blocks) {
    const uid = tag(block, 'UID');
    const name = unescape(tag(block, 'Name'));
    if (!uid || uid === '0' || !name) continue; // project-summary row / blanks
    const level = Math.max(1, Number(tag(block, 'OutlineLevel')) || 1);
    const depth = Math.min(level, 3); // deeper levels flatten to task level
    const preds = [...block.matchAll(/<PredecessorLink>[\s\S]*?<PredecessorUID>(\d+)<\/PredecessorUID>[\s\S]*?<\/PredecessorLink>/g)]
      .map((m) => `msp-${m[1]}`);
    const pct = Number(tag(block, 'PercentComplete')) || 0;
    const t = {
      id: `msp-${uid}`,
      parentId: depth > 1 ? (parents[depth - 1] || '') : '',
      depth,
      phase: depth === 1 ? name : '',
      activity: depth === 2 ? name : '',
      task: depth === 3 ? name : '',
      name,
      plannedStartDate: day(tag(block, 'Start')),
      plannedEndDate: day(tag(block, 'Finish')),
      actualProgress: pct,
      predecessors: preds.join(','),
    };
    tasks.push(t);
    parents[depth] = t.id;
    for (let d = depth + 1; d <= 3; d++) delete parents[d]; // reset deeper chain
  }
  return tasks;
}