export function parseMsProjectXml(xml) {
  // Fully linear extract (indexOf/slice) — no dynamic RegExp and no lazy
  // [\s\S]*? block collectors (those can quadratic-backtrack on truncated input).
  const tag = (block, name) => {
    const openingTag = `<${name}>`;
    const closingTag = `</${name}>`;
    const valueStart = block.indexOf(openingTag);
    if (valueStart === -1) return '';
    const contentStart = valueStart + openingTag.length;
    const valueEnd = block.indexOf(closingTag, contentStart);
    return valueEnd === -1 ? '' : block.slice(contentStart, valueEnd).trim();
  };
  const collectBlocks = (source, openTag, closeTag) => {
    const out = [];
    let from = 0;
    for (;;) {
      const start = source.indexOf(openTag, from);
      if (start === -1) break;
      const contentStart = start + openTag.length;
      const end = source.indexOf(closeTag, contentStart);
      // Incomplete open tag: stop linearly (do not rescan the remainder).
      if (end === -1) break;
      out.push(source.slice(start, end + closeTag.length));
      from = end + closeTag.length;
    }
    return out;
  };
  const predecessorIds = (block) => {
    const ids = [];
    for (const link of collectBlocks(block, '<PredecessorLink>', '</PredecessorLink>')) {
      const uid = tag(link, 'PredecessorUID');
      if (/^\d+$/.test(uid)) ids.push(`msp-${uid}`);
    }
    return ids;
  };
  const unescape = (s) => s
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '\"')
    .replace(/&apos;/g, "'").replace(/&amp;/g, '&');
  const day = (s) => (/^\d{4}-\d{2}-\d{2}/.test(s) ? s.slice(0, 10) : '');
  const tasks = [];
  const parents = {}; // depth -> last task id at that depth
  const blocks = collectBlocks(String(xml || ''), '<Task>', '</Task>');
  for (const block of blocks) {
    const uid = tag(block, 'UID');
    const name = unescape(tag(block, 'Name'));
    if (!uid || uid === '0' || !name) continue; // project-summary row / blanks
    const level = Math.max(1, Number(tag(block, 'OutlineLevel')) || 1);
    const depth = Math.min(level, 3); // deeper levels flatten to task level
    const preds = predecessorIds(block);
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