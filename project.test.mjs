import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { targetUrl, auditHeaders, extractLinks, robotsPolicy, scanSite, importScannerReport } from './index.mjs';
async function serve(t, handler) {const s=http.createServer(handler).listen(0,'127.0.0.1');await once(s,'listening');t.after(()=>{s.closeAllConnections();s.close();});return `http://127.0.0.1:${s.address().port}`;}
test('rejects credential-bearing URLs and unsupported protocols',()=>{for(const u of ['file:///etc/passwd','http://u:p@example.com','https://example.com/?token=a','https://example.com/#a'])assert.throws(()=>targetUrl(u));});
test('header checks distinguish enforced CSP, report-only CSP and broad policies',()=>{
  let c=auditHeaders({'content-security-policy-report-only':"default-src 'self'"},'https://example.test');assert.equal(c.find(c=>c.id==='headers.csp').status,'warn');
  c=auditHeaders({'content-security-policy':"default-src 'self'; script-src 'unsafe-inline'; frame-ancestors 'none'"},'https://example.test');assert.equal(c.find(c=>c.id==='headers.csp-script').status,'warn');assert.equal(c.find(c=>c.id==='headers.framing').status,'pass');
});
test('session cookies are checked without retaining cookie values',()=>{
  const h=new Headers();h.append('set-cookie','session=SYNTHETIC_SECRET; Path=/; SameSite=None');
  const c=auditHeaders(h,'https://example.test');assert.ok(c.some(c=>c.id.endsWith('.httponly')));assert.ok(c.some(c=>c.id.endsWith('.none-secure')));assert.ok(!JSON.stringify(c).includes('SYNTHETIC_SECRET'));
});
test('static link extraction respects origin, fragments and query exclusions',()=>{
  const links=extractLinks('<a href="/a#b">A</a><a href="https://evil.test">X</a><a href="/delete">D</a><a href="/q?token=secret">Q</a><a href=/b>B</a>','https://example.test/');assert.deepEqual(links,['https://example.test/a','https://example.test/b']);
});
test('robots longest matching rules, wildcard and allow precedence',()=>{
  const allowed=robotsPolicy('User-agent: *\nDisallow: /private\nAllow: /private/public\nDisallow: /*.pdf$');assert.equal(allowed('/private/x'),false);assert.equal(allowed('/private/public/x'),true);assert.equal(allowed('/a.pdf'),false);assert.equal(allowed('/a.pdf/x'),true);
});
test('specific robots user-agent rules take precedence over wildcard groups',()=>{
 const allowed=robotsPolicy('User-agent: *\nAllow: /\nUser-agent: WebAuditWorkbench\nDisallow: /');assert.equal(allowed('/a'),false);
});
test('actual HTTP crawl obeys bounds, skips robots paths and never follows off-origin redirects',async t=>{
  const seen=[];const root=await serve(t,(req,res)=>{seen.push(req.url);if(req.url==='/robots.txt'){res.end('User-agent: *\nDisallow: /private');return;}if(req.url==='/redirect'){res.writeHead(302,{location:'https://example.com'});res.end();return;}res.setHeader('content-type','text/html');res.end('<a href="/a">A</a><a href="/private">P</a><a href="/redirect">R</a>');});
  const report=await scanSite(root,{maxPages:3,delay:0});assert.equal(report.pages.length,3);assert.ok(!seen.includes('/private'));assert.ok(report.skipped.some(s=>s.reason.includes('redirect outside')));
});
test('page limit includes failed requests and is never exceeded',async t=>{
  const root=await serve(t,(req,res)=>{if(req.url==='/robots.txt'){res.writeHead(404);res.end();return;}res.setHeader('content-type','text/html');res.end('<a href="/a">a</a><a href="/b">b</a>');});const r=await scanSite(root,{maxPages:1,delay:0});assert.equal(r.pages.length,1);assert.equal(r.truncated,true);
});
test('robots failures fail closed and large bodies produce a bounded error',async()=>{
  const a=await scanSite('https://example.test',{fetchImpl:async()=>new Response('',{status:503}),delay:0});assert.equal(a.pages.length,0);assert.equal(a.checks[0].status,'fail');
  const b=await scanSite('https://example.test',{maxBodyBytes:10,fetchImpl:async url=>url.endsWith('robots.txt')?new Response('',{status:404}):new Response('x'.repeat(100),{headers:{'content-type':'text/html'}}),delay:0});assert.ok(b.checks.some(c=>c.id==='request.failed'));
});
test('imports ZAP findings without raw request/response bodies',()=>{
  const r=importScannerReport({site:[{'@name':'https://example.test',alerts:[{pluginid:'10020',riskcode:'2',name:'Example',instances:[{uri:'https://example.test/a?token=secret',request:'SECRET'}]}]}]},'zap');assert.equal(r.checks[0].status,'fail');assert.ok(!JSON.stringify(r).includes('SECRET'));assert.ok(!JSON.stringify(r).includes('token='));
});
test('imports Nuclei JSONL records without extracted secrets',()=>{
  const r=importScannerReport([{'template-id':'test',info:{name:'Test',severity:'high'},'matched-at':'https://example.test/','extracted-results':['SECRET']}],'nuclei');assert.equal(r.checks[0].status,'fail');assert.ok(!JSON.stringify(r).includes('SECRET'));
});
test('malformed imports and invalid limits do not silently pass',async()=>{assert.throws(()=>importScannerReport({},'zap'));assert.throws(()=>importScannerReport([{}],'nuclei'));await assert.rejects(scanSite('https://example.test',{maxPages:0}));});
