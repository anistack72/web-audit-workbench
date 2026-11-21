#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { scanSite, importScannerReport } from './index.mjs';
import { options, formatReport, exitCode, clean } from './support.mjs';
try {
  const args = options({ pages:{type:'string',default:'10'}, depth:{type:'string',default:'2'}, timeout:{type:'string',default:'5000'}, delay:{type:'string',default:'200'}, import:{type:'string'}, source:{type:'string'}, strict:{type:'boolean'} });
  if (args.help) console.log('Web Audit Workbench\n\nnode cli.mjs https://your-site.example [--pages 10] [--depth 2] [--delay 200]\n  [--timeout 5000] [--format text|json|markdown|html] [--strict]\nnode cli.mjs --import report.json --source zap --format html\nnode cli.mjs --import results.jsonl --source nuclei --format markdown\n\nUse on sites you own or are authorized to assess. Crawling stays within one origin.');
  else {
    let report;
    if (args.import) {
      if (args.positionals.length || !args.source) throw new Error('Import requires --source zap|nuclei and no target URL');
      if ((await stat(args.import)).size > 25*1024*1024) throw new Error('Import exceeds 25 MiB');
      const raw = await readFile(args.import,'utf8');
      const data = args.source === 'nuclei' ? raw.split(/\r?\n/).filter(s=>s.trim()).map(s=>JSON.parse(s)) : JSON.parse(raw);
      report = importScannerReport(data,args.source);
    } else {
      if (args.positionals.length!==1) throw new Error('Provide exactly one target URL');
      report = await scanSite(args.positionals[0],{maxPages:args.pages,maxDepth:args.depth,timeout:args.timeout,delay:args.delay});
    }
    console.log(formatReport(report,args.format));process.exitCode=exitCode(report,args.strict);
  }
} catch(error) {console.error(`Web Audit Workbench: ${clean(error.message)}`);process.exitCode=2;}
