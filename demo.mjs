import http from 'node:http';import { once } from 'node:events';
import { scanSite } from './index.mjs';import { formatReport } from './support.mjs';
const server=http.createServer((req,res)=>{if(req.url==='/robots.txt'){res.end('User-agent: *\nDisallow: /private');return;}res.setHeader('content-type','text/html');res.setHeader('x-content-type-options','nosniff');res.setHeader('content-security-policy',"default-src 'self'; frame-ancestors 'none'");res.setHeader('referrer-policy','no-referrer');res.end('<main>Synthetic fixture website</main><a href="/docs">Docs</a><a href="/private">Private</a>');}).listen(0,'127.0.0.1');await once(server,'listening');
try {const report=await scanSite(`http://127.0.0.1:${server.address().port}`,{delay:0,maxPages:3});report.summary='SYNTHETIC FIXTURE DEMO — only a temporary local website was audited. '+report.summary;console.log(formatReport(report,process.argv[2]??'text'));}
finally {server.closeAllConnections();server.close();}
