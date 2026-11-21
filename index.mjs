import { clean, integer } from './support.mjs';

export function targetUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error('Provide a complete HTTP(S) URL'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Targets must use HTTP(S), without embedded credentials, query or fragment');
  return url;
}

function observation(id, status, message, url) { return { id, status, message: `${new URL(url).pathname}: ${message}`, url }; }
export function auditHeaders(headers, url) {
  const h = new Headers(headers), checks = [], https = new URL(url).protocol === 'https:';
  const add = (id, status, message) => checks.push(observation(id,status,message,url));
  add('transport.https', https ? 'pass' : 'warn', https ? 'HTTPS used for this response.' : 'HTTP transport; use HTTPS for production traffic.');
  if (https) {
    const hsts = h.get('strict-transport-security') ?? '', age = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(hsts);
    add('headers.hsts', age && Number(age[1]) > 0 ? 'pass' : 'warn', age && Number(age[1]) > 0 ? `HSTS max-age is ${age[1]} seconds. Confirm subdomain policy before changing it.` : 'No effective HSTS max-age observed.');
  }
  add('headers.nosniff', h.get('x-content-type-options')?.toLowerCase() === 'nosniff' ? 'pass' : 'warn', h.get('x-content-type-options')?.toLowerCase() === 'nosniff' ? 'MIME sniffing protection is present.' : 'Set X-Content-Type-Options: nosniff for applicable responses.');
  const policy = h.get('content-security-policy');
  const directives = new Map();
  for (const part of (policy ?? '').split(';')) {
    const [name,...values] = part.trim().split(/\s+/);
    if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(),values);
  }
  add('headers.csp', policy ? 'pass' : 'warn', policy ? 'An enforced CSP header is present; its full semantics require application review.' : 'No enforced Content-Security-Policy observed. A report-only policy is not enforcement.');
  if (policy) {
    const scripts = directives.get('script-src') ?? directives.get('default-src');
    const nonceOrHash = scripts?.some(v => /^'(nonce-|sha(?:256|384|512)-)/.test(v));
    const permissive = !scripts || scripts.includes('*') || scripts.includes("'unsafe-eval'") || (scripts.includes("'unsafe-inline'") && !nonceOrHash);
    add('headers.csp-script', permissive ? 'warn' : 'pass', permissive ? 'Script policy appears broad or permits inline/eval execution. Review it in the application context.' : 'No obvious wildcard, eval or unqualified unsafe-inline script allowance detected by this limited check.');
  }
  const ancestors = directives.get('frame-ancestors');
  const xfo = (h.get('x-frame-options') ?? '').trim().toUpperCase();
  add('headers.framing', ancestors?.length || ['DENY','SAMEORIGIN'].includes(xfo) ? 'pass' : 'warn', ancestors?.length || ['DENY','SAMEORIGIN'].includes(xfo) ? 'A framing policy is present; confirm it matches intended embedding.' : 'Consider CSP frame-ancestors or an appropriate X-Frame-Options policy.');
  const referrer = (h.get('referrer-policy') ?? '').split(',').map(s => s.trim()).filter(Boolean).at(-1);
  add('headers.referrer', ['no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin'].includes(referrer) ? 'pass' : 'warn', referrer ? `Explicit referrer policy: ${clean(referrer)}.` : 'No explicit Referrer-Policy observed; browser defaults vary by client.');
  const cookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [];
  for (const [index,cookie] of cookies.entries()) {
    const name = clean(cookie.split('=',1)[0]).slice(0,80);
    if (https && !/(?:^|;)\s*secure\s*(?:;|$)/i.test(cookie)) add(`cookies.${index}.secure`, 'warn', `Cookie ${name} lacks Secure. Cookie values are omitted.`);
    if (/session|auth|token|(?:^|_)sid$/i.test(name) && !/(?:^|;)\s*httponly\s*(?:;|$)/i.test(cookie)) add(`cookies.${index}.httponly`, 'warn', `Session-like cookie ${name} lacks HttpOnly; verify whether JavaScript needs access.`);
    if (!/(?:^|;)\s*samesite\s*=\s*(lax|strict|none)\s*(?:;|$)/i.test(cookie)) add(`cookies.${index}.samesite`, 'warn', `Cookie ${name} lacks an explicit valid SameSite value.`);
    if (/(?:^|;)\s*samesite\s*=\s*none\s*(?:;|$)/i.test(cookie) && !/(?:^|;)\s*secure\s*(?:;|$)/i.test(cookie)) add(`cookies.${index}.none-secure`, 'warn', `Cookie ${name} uses SameSite=None without Secure.`);
  }
  return checks;
}

export function extractLinks(html, base) {
  const links = new Set(), origin = new URL(base).origin;
  const regex = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))/gi;
  for (const match of html.matchAll(regex)) {
    try {
      const raw = (match[1] ?? match[2] ?? match[3]).replace(/&amp;/gi,'&');
      const url = new URL(raw,base); url.hash = '';
      if (url.origin === origin && ['http:','https:'].includes(url.protocol) && !url.search && !url.username && !url.password && !/(?:logout|signout|delete|remove)(?:\/|$)/i.test(url.pathname)) links.add(url.href);
    } catch { /* Ignore malformed hrefs; this is a static HTML link extractor. */ }
  }
  return [...links];
}

export function robotsPolicy(text) {
  const groups=[];let group={agents:[],rules:[]},inRules=false;
  for (const line of text.split(/\r?\n/)) {
    const value = line.replace(/#.*/,'').trim(), split = value.indexOf(':');
    if (split < 0) continue;
    const key = value.slice(0,split).trim().toLowerCase(), body = value.slice(split+1).trim();
    if (key === 'user-agent') {
      if(inRules){groups.push(group);group={agents:[],rules:[]};inRules=false;}
      group.agents.push(body.toLowerCase());
    }
    else if (['allow','disallow'].includes(key)) {
      inRules = true;
      if (group.agents.length && body) group.rules.push({ allow: key === 'allow', path: body });
    }
  }
  groups.push(group);
  const matching=groups.map(g=>({...g,specificity:Math.max(-1,...g.agents.map(a=>a==='*'?0:'webauditworkbench'.includes(a)&&a.length?a.length:-1))})).filter(g=>g.specificity>=0);
  const specificity=Math.max(-1,...matching.map(g=>g.specificity));
  const rules=matching.filter(g=>g.specificity===specificity).flatMap(g=>g.rules);
  return pathname => {
    const matches = rules.filter(r => {
      const end = r.path.endsWith('$');
      const pattern = r.path.replace(/\$$/,'').split('*').map(p => p.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')).join('.*');
      return new RegExp('^' + pattern + (end ? '$' : '')).test(pathname);
    }).sort((a,b) => b.path.length - a.path.length || Number(b.allow) - Number(a.allow));
    return matches[0]?.allow ?? true;
  };
}

async function boundedText(response, maxBytes) {
  const reader = response.body?.getReader(); if (!reader) return '';
  let size = 0; const chunks = [];
  try {
    while (true) {
      const { done,value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > maxBytes) throw new Error('Response body exceeds the configured limit');
      chunks.push(Buffer.from(value));
    }
  } finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks).toString('utf8');
}

export async function scanSite(input, { maxPages = 10, maxDepth = 2, timeout = 5000, delay = 200, maxBodyBytes = 1024 * 1024, fetchImpl = fetch, signal } = {}) {
  const target = targetUrl(input);
  maxPages = integer(maxPages,'maxPages',1,100); maxDepth = integer(maxDepth,'maxDepth',0,5);
  timeout = integer(timeout,'timeout',1,30000); delay = integer(delay,'delay',0,10000); maxBodyBytes = integer(maxBodyBytes,'maxBodyBytes',1,10*1024*1024);
  const checks = [], pages = [], skipped = [], visited = new Set(), queue = [{ url:target.href,depth:0 }];
  const fetchPage = async (url, consume) => {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(),timeout);
    try {
      const response = await fetchImpl(url,{ method:'GET', redirect:'manual', signal:signal ? AbortSignal.any([signal,controller.signal]) : controller.signal, headers: { 'User-Agent':'WebAuditWorkbench/0.1 (+https://github.com/anistack72/web-audit-workbench)', Accept:'text/html,text/plain;q=0.9,*/*;q=0.1' } });
      return await consume(response);
    } finally { clearTimeout(timer); }
  };
  let allowed = () => true;
  try {
    await fetchPage(target.origin+'/robots.txt',async response => {
      if (response.status === 200) allowed = robotsPolicy(await boundedText(response,128*1024));
      else if (response.status !== 404 && response.status !== 410) throw new Error('robots.txt could not be established');
      else await response.body?.cancel();
    });
  } catch {
    return { schemaVersion:1,tool:'Web Audit Workbench',target:target.href,summary:'Scan stopped because robots.txt could not be read reliably.',checks:[{id:'crawl.robots',status:'fail',message:'Check connectivity and robots.txt before retrying.'}],pages,skipped };
  }
  while (queue.length && pages.length < maxPages) {
    if (signal?.aborted) throw signal.reason ?? new Error('Scan cancelled');
    const item = queue.shift(); if (visited.has(item.url)) continue; visited.add(item.url);
    if (!allowed(new URL(item.url).pathname)) { skipped.push({url:item.url,reason:'robots.txt'}); continue; }
    if (pages.length && delay) await new Promise(resolve => setTimeout(resolve,delay));
    try {
      await fetchPage(item.url,async response => {
        pages.push({url:item.url,status:response.status,depth:item.depth});
        if (response.status >= 300 && response.status < 400) {
          const destination = response.headers.get('location'); await response.body?.cancel();
          try {
            const next = targetUrl(new URL(destination,item.url).href);
            if (next.origin === target.origin && item.depth < maxDepth) queue.push({url:next.href,depth:item.depth+1});
            else skipped.push({url:item.url,reason:'redirect outside origin or depth limit'});
          } catch { skipped.push({url:item.url,reason:'redirect with unsupported URL'}); }
          return;
        }
        if (response.status >= 400) checks.push(observation('http.status','warn',`HTTP ${response.status}; this response may not represent the normal application page.`,item.url));
        checks.push(...auditHeaders(response.headers,item.url));
        const type = response.headers.get('content-type') ?? '';
        if (!/text\/html|application\/xhtml\+xml/i.test(type)) { await response.body?.cancel(); return; }
        const html = await boundedText(response,maxBodyBytes);
        if (target.protocol === 'https:' && /<(?:script|img|iframe|link|source|audio|video)\b[^>]*(?:src|href)\s*=\s*["']http:\/\//i.test(html)) checks.push(observation('content.mixed','warn','Static HTML appears to reference an HTTP resource. Confirm the resource and browser behavior.',item.url));
        if (item.depth < maxDepth) for (const url of extractLinks(html,item.url)) {
          if (queue.length + visited.size >= maxPages * 10) break;
          if (!visited.has(url)) queue.push({url,depth:item.depth+1});
        }
      });
    } catch (error) {
      if (!pages.some(p => p.url === item.url)) pages.push({url:item.url,status:null,depth:item.depth});
      checks.push(observation('request.failed','fail',clean(error.name === 'AbortError' ? 'Request timed out.' : error.message),item.url));
    }
  }
  if (!pages.length) checks.push({id:'crawl.empty',status:'warn',message:'No pages fetched. Review robots.txt and the target path.'});
  return {schemaVersion:1,tool:'Web Audit Workbench',target:target.href,summary:`${pages.length} page(s) requested within one origin. Passive configuration observations; no exploit payloads or form submissions.`,checks,pages,skipped,limits:{maxPages,maxDepth,timeout,delay,maxBodyBytes},truncated:queue.length>0,limitations:['Static HTML only; JavaScript routes and authenticated pages are not exercised.','Header presence is not proof of a secure policy. Review findings in context.','One additional request reads robots.txt before page crawling.']};
}

function safeImportedUrl(raw) { try { const u = new URL(raw); u.username='';u.password='';u.search='';u.hash=''; return u.href; } catch {return 'not supplied';} }
export function importScannerReport(data, source) {
  const checks=[];
  if (source === 'zap') {
    if (!data || !Array.isArray(data.site)) throw new Error('ZAP JSON must contain site[]');
    for (const site of data.site) {
      if (!Array.isArray(site.alerts)) throw new Error('ZAP site must contain alerts[]');
      for (const a of site.alerts) {
        if (!a || a.pluginid === undefined) throw new Error('Malformed ZAP alert');
        checks.push({id:`zap.${clean(a.pluginid)}`,status:Number(a.riskcode)>=2?'fail':'warn',message:clean(a.name ?? a.alert),url:safeImportedUrl(a.instances?.[0]?.uri ?? site['@name'])});
      }
    }
  } else if (source === 'nuclei') {
    if (!Array.isArray(data)) throw new Error('Nuclei input must be parsed JSONL records');
    for (const f of data) {
      if (!f || typeof f['template-id'] !== 'string' || !f.info) throw new Error('Malformed Nuclei finding');
      checks.push({id:`nuclei.${clean(f['template-id'])}`,status:['medium','high','critical'].includes(String(f.info.severity).toLowerCase())?'fail':'warn',message:clean(f.info.name ?? f['template-id']),url:safeImportedUrl(f['matched-at'])});
    }
  } else throw new Error('Import source must be zap or nuclei');
  if (!checks.length) checks.push({id:'import.empty',status:'pass',message:'No findings in the supplied scanner report. Scan coverage has not been verified.'});
  return {schemaVersion:1,tool:'Web Audit Workbench',summary:`Imported ${checks.length} observation(s) from ${source}. Scanner execution and raw request/response bodies are not included.`,checks,source};
}
