import { parseArgs } from 'node:util';

export const clean = value => String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, 2000);
export const escapeHtml = value => String(value ?? '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const md = value => clean(value).replace(/\|/g, '\\|').replace(/`/g, "'");

export function options(extra = {}) {
  const { values, positionals } = parseArgs({
    options: { help: { type: 'boolean', short: 'h' }, format: { type: 'string', default: 'text' }, ...extra },
    allowPositionals: true, strict: true,
  });
  if (!['text', 'json', 'markdown', 'html'].includes(values.format)) throw new Error('format must be text, json, markdown or html');
  return { ...values, positionals };
}

export function integer(value, name, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${name} must be an integer from ${min} to ${max}`);
  return n;
}

export function formatReport(report, format = 'text') {
  if (format === 'json') return JSON.stringify(report, null, 2);
  const title = clean(report.tool);
  const checks = report.checks ?? [];
  if (format === 'html') {
    const rows = checks.map(c => `<tr><td><span class="${escapeHtml(c.status)}">${escapeHtml(c.status)}</span></td><td>${escapeHtml(c.id)}</td><td>${escapeHtml(c.message)}</td></tr>`).join('');
    return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title><style>body{font:15px/1.6 system-ui;background:#0b1014;color:#e7eceb;margin:0;padding:6vw;max-width:1200px}h1{font-size:clamp(28px,5vw,52px);letter-spacing:-.04em}small{color:#92a4a3}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:16px 12px;border-bottom:1px solid #263235;vertical-align:top;overflow-wrap:anywhere}.pass{color:#9be5ba}.warn{color:#f4d483}.fail{color:#ffa8a8}pre{white-space:pre-wrap;overflow-wrap:anywhere}details{margin-top:32px}a{color:#9be5ba}</style><small>ANIS MOSBAH / DEVELOPER TOOLS</small><h1>${escapeHtml(title)}</h1><p>${escapeHtml(report.summary ?? '')}</p><table><thead><tr><th>Result</th><th>Check</th><th>Evidence / next step</th></tr></thead><tbody>${rows}</tbody></table><details><summary>Report data</summary><pre>${escapeHtml(JSON.stringify(report, null, 2))}</pre></details><p><small>Observations from this run are not a complete security or quality assessment.</small></p></html>`;
  }
  if (format === 'markdown') {
    return `# ${md(title)}\n\n${md(report.summary ?? '')}\n\n| Result | Check | Evidence / next step |\n| :--- | :--- | :--- |\n${checks.map(c => `| ${md(c.status)} | ${md(c.id)} | ${md(c.message)} |`).join('\n')}\n\n\`\`\`json\n${JSON.stringify(report, null, 2)}\n\`\`\`\n`;
  }
  return `${title}\n${'─'.repeat(Math.min(title.length, 64))}\n${clean(report.summary ?? '')}\n\n${checks.map(c => `${c.status.toUpperCase().padEnd(5)} ${clean(c.id)}\n      ${clean(c.message)}`).join('\n')}\n`;
}

export function exitCode(report, strict = false) {
  return report.checks.some(c => c.status === 'fail' || (strict && c.status === 'warn')) ? 1 : 0;
}

export async function readJsonBody(response, maxBytes = 2 * 1024 * 1024) {
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  if (Number(response.headers.get('content-length')) > maxBytes) {
    await response.body?.cancel();
    throw new Error('Response exceeds the size limit');
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error('Empty response body');
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Error('Response exceeds the size limit');
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel().catch(() => {}); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new Error('Response is not valid JSON'); }
}
