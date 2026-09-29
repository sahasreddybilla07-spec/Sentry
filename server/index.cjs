const express = require('express');
const multer = require('multer');
const AdmZip = require('adm-zip');
const PDFDocument = require('pdfkit');
const path = require('path');
const crypto = require('crypto');
const app = express();
app.use((req,res,next)=>{res.setHeader('Access-Control-Allow-Origin','*');res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type');if(req.method==='OPTIONS')return res.sendStatus(204);next()});
app.use(express.json({limit:'10mb'}));
const upload = multer({storage: multer.memoryStorage(), limits:{fileSize:100*1024*1024}});
const runs = new Map();
const SOURCE_EXT = /\.(js|jsx|ts|tsx|cjs|mjs|py|java|go|rb|php|cs|json|yml|yaml)$/i;
function lineAt(text,index){return text.slice(0,index).split('\n').length}
function snippet(text,line){const rows=text.split('\n'),from=Math.max(0,line-3),to=Math.min(rows.length,line+3);return rows.slice(from,to).map((x,i)=>`${String(from+i+1).padStart(4)} | ${x}`).join('\n')}
function controls(context,type){const c=[];if(/https:|requireHttps|httpsOnly/i.test(context))c.push('HTTPS enforcement');if(/allowlist|allowedHosts|allowed.*host/i.test(context))c.push('Hostname allowlist validation');if(/private|loopback|reserved|127\.0\.0\.1|169\.254/i.test(context))c.push('Private/local/reserved address blocking');if(/dns\.|resolve\(|lookup\(/i.test(context))c.push('DNS resolution validation');if(/pin(ned|ning)|localAddress|agent/i.test(context))c.push('Connection pinning');if(/auth|session|token|bearer|requireUser/i.test(context)&&type==='idor')c.push('Authentication/session validation');if(/authorize|ownership|ownerId|permission|role|canAccess/i.test(context)&&type==='idor')c.push('Resource authorization check');return c}
function finding(file,text,index,ruleId,title,category,severity,reason,type,recommendation){const line=lineAt(text,index),context=text.split('\n').slice(Math.max(0,line-8),line+8).join('\n'),securityControls=controls(context,type);let confidence=type==='secret'?86:type==='idor'?64:70;if(securityControls.length)confidence=Math.max(12,confidence-securityControls.length*18);return {id:'',ruleId,title,category,severity:securityControls.length>=2?'informational':severity,confidence,status:securityControls.length>=2?'NOT CONFIRMED':'NEEDS REVIEW',file,line,column:1,evidence:snippet(text,line),description:reason,reason,securityControls,recommendation,affectedAsset:path.basename(file),createdAt:new Date().toISOString()}}
function analyze(files){const findings=[];for(const f of files){const text=f.content,add=(idx,...args)=>findings.push(finding(f.path,text,idx,...args));let m;const outbound=/(?:fetch\s*\(|axios\.(?:get|post|request)\s*\(|https?\.request\s*\()/g;while((m=outbound.exec(text))){const nearby=text.slice(Math.max(0,m.index-700),m.index+900);if(/url|uri|endpoint|webhook|req\.|body\.|params\.|query\./i.test(nearby))add(m.index,'SSRF-001','Potential SSRF in outbound request','SSRF','medium','User-influenced URL or endpoint appears to reach an outbound request API.','ssrf','Validate destination URLs, block private/reserved addresses, and pin validated connections.')}const resource=/(?:req\.(?:params|query|body)\.(?:userId|accountId|profileId|documentId|resourceId)|params\.(?:userId|accountId|profileId|documentId|resourceId))/g;while((m=resource.exec(text)))add(m.index,'IDOR-001','Potential resource authorization gap','Broken Access Control / IDOR','medium','A request-derived resource identifier is used in a sensitive code path; authorization evidence was evaluated nearby.','idor','Derive identity from a validated session and enforce ownership or role authorization before access.');const secret=/(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]/gi;while((m=secret.exec(text))){if(!/example|placeholder|changeme|your[_-]/i.test(m[0]))add(m.index,'SECRET-001','Potential hardcoded secret','Sensitive Information','high','A credential-like literal was found in source code.','secret','Move secrets to a managed secret store or environment variable and rotate exposed values.')}const cors=/Access-Control-Allow-Origin\s*[:=]\s*['\"]\*|origin\s*:\s*['\"]\*/g;while((m=cors.exec(text)))add(m.index,'CONFIG-001','Permissive CORS configuration','Security Configuration','medium','Wildcard CORS configuration may expose browser-facing endpoints.','config','Restrict allowed origins to trusted application origins.')}findings.forEach((f,i)=>f.id=`F-${String(i+1).padStart(3,'0')}`);return findings}
function unpack(buffer){const zip=new AdmZip(buffer),files=[];for(const entry of zip.getEntries()){if(entry.isDirectory||!SOURCE_EXT.test(entry.entryName)||entry.header.size>1024*1024)continue;files.push({path:entry.entryName,content:entry.getData().toString('utf8')})}return files}
app.get('/',(req,res)=>res.type('html').send('<main style="font-family:system-ui;padding:3rem;color:#172235"><h1>Sentinel Assessment API</h1><p>The source-analysis service is running.</p><p>Use <code>POST /api/assess</code> with a ZIP archive, or check <a href="/api/health">/api/health</a>.</p></main>'));
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.post('/api/assess',upload.single('source'),(req,res)=>{try{if(!req.file||!req.file.originalname.toLowerCase().endsWith('.zip'))return res.status(400).json({error:'Upload a ZIP archive.'});const files=unpack(req.file.buffer);if(!files.length)return res.status(400).json({error:'No supported source files found in ZIP.'});const findings=analyze(files),id=`ASM-${crypto.randomUUID().slice(0,8).toUpperCase()}`,run={assessmentId:id,application:req.body.application||path.basename(req.file.originalname,'.zip'),startTime:new Date().toISOString(),endTime:new Date().toISOString(),status:'COMPLETED',filesAnalyzed:files.length,rulesExecuted:['SSRF-001','IDOR-001','SECRET-001','CONFIG-001'],findings,inventory:files.map(f=>f.path),scope:'Uploaded source-code archive · static analysis only'};runs.set(id,run);res.json(run)}catch(e){res.status(400).json({error:`Unable to inspect archive: ${e.message}`})}});
app.get('/api/runs/:id',(req,res)=>runs.has(req.params.id)?res.json(runs.get(req.params.id)):res.status(404).json({error:'Assessment not found'}));
function safeFilename(name){return String(name||'report').replace(/[^a-z0-9-_]+/gi,'-').replace(/^-+|-+$/g,'')||'report'}
const DOC_COLORS={navy:'#16394f',accent:'#2674db',textDark:'#172235',textGray:'#60718b',headRow:'#e4edf4',stripe:'#f8fafc',border:'#d6deea',red:'#c0392b',amber:'#b7791f',green:'#1f7a4d'};
function severityColor(sev){const s=String(sev||'').toLowerCase();return s==='critical'||s==='high'?DOC_COLORS.red:s==='medium'?DOC_COLORS.amber:DOC_COLORS.green}
function severityRank(s){return {critical:0,high:1,medium:2,low:3,informational:4}[String(s||'').toLowerCase()]??5}
function capFirst(s){s=String(s||'');return s.charAt(0).toUpperCase()+s.slice(1).toLowerCase()}
function fitText(doc,text,maxWidth,fontSize,font){doc.font(font||'Helvetica').fontSize(fontSize);text=String(text||'');if(doc.widthOfString(text)<=maxWidth)return text;let t=text;while(t.length>1&&doc.widthOfString(t+'…')>maxWidth)t=t.slice(0,-1);return t+'…'}
function drawDocHeader(doc,M,CW,badge,title,assessmentId,dateStr){
 doc.font('Helvetica-Bold').fontSize(9).fillColor(DOC_COLORS.textGray).text(badge.toUpperCase(),M,M);
 doc.font('Helvetica-Bold').fontSize(20).fillColor(DOC_COLORS.textDark).text(title,M,doc.y+3);
 const metaY=doc.y+3;
 doc.font('Helvetica').fontSize(9.5).fillColor(DOC_COLORS.textGray).text(`Assessment ID: ${assessmentId}`,M,metaY);
 doc.font('Helvetica').fontSize(9.5).fillColor(DOC_COLORS.textGray).text(`Generated ${dateStr}`,M,metaY,{width:CW,align:'right'});
 const ruleY=metaY+16;
 doc.strokeColor(DOC_COLORS.accent).lineWidth(1.5).moveTo(M,ruleY).lineTo(M+CW,ruleY).stroke();
 doc.y=ruleY+14;
}
function drawSectionTitle(doc,M,text){doc.font('Helvetica-Bold').fontSize(13).fillColor(DOC_COLORS.navy).text(text,M,doc.y);doc.y+=4}
function drawTable(doc,x,startY,cols,rows,opts={}){
 const headerH=opts.headerH||20,rowH=opts.rowH||17,fontSize=opts.fontSize||9;
 const M=doc.page.margins.left,pageBottom=doc.page.height-doc.page.margins.bottom,tableW=cols.reduce((a,c)=>a+c.w,0);
 let y=startY;
 const drawHeader=()=>{let cx=x;doc.rect(x,y,tableW,headerH).fill(DOC_COLORS.headRow);cols.forEach(c=>{doc.font('Helvetica-Bold').fontSize(fontSize).fillColor(DOC_COLORS.navy).text(c.label,cx+6,y+6,{width:c.w-10});cx+=c.w});y+=headerH};
 drawHeader();
 if(!rows.length){doc.font('Helvetica').fontSize(fontSize).fillColor(DOC_COLORS.textGray).text(opts.emptyText||'No data available.',x+6,y+5);y+=rowH}
 rows.forEach((row,i)=>{
  if(y+rowH>pageBottom){doc.addPage();y=doc.page.margins.top;drawHeader()}
  if(i%2===1)doc.rect(x,y,tableW,rowH).fill(DOC_COLORS.stripe);
  let cx=x;
  cols.forEach(c=>{
   const raw=row[c.key];
   const val=raw==null?'':String(raw);
   const text=c.fit?fitText(doc,val,c.w-10,fontSize):val;
   if(c.dot)doc.circle(cx+8,y+rowH/2,3).fill(c.dot(row));
   doc.font(c.bold?'Helvetica-Bold':'Helvetica').fontSize(fontSize).fillColor(c.color?c.color(row):DOC_COLORS.textDark).text(text,cx+(c.dot?16:6),y+5,{width:c.w-(c.dot?20:10)});
   cx+=c.w;
  });
  y+=rowH;
 });
 doc.strokeColor(DOC_COLORS.border).lineWidth(1).rect(x,startY,tableW,y-startY).stroke();
 doc.y=y;
 return y;
}
function renderReportPdf(res,data){
 const doc=new PDFDocument({margin:44,size:'A4',bufferPages:true});
 const filename=`${safeFilename(data.application||data.title)}-${safeFilename(data.assessmentId)}-report.pdf`;
 res.setHeader('Content-Type','application/pdf');
 res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
 doc.pipe(res);
 const M=44,CW=doc.page.width-2*M;
 const dateStr=data.generatedAt?new Date(data.generatedAt).toLocaleString():new Date().toLocaleString();
 const findings=data.findings||[];
 drawDocHeader(doc,M,CW,'Authorized static source analysis',data.title||`${data.application} Security Assessment`,data.assessmentId||'N/A',dateStr);
 drawSectionTitle(doc,M,'Executive summary');
 doc.font('Helvetica').fontSize(10.5).fillColor(DOC_COLORS.textDark).text(data.summary||'No summary available.',M,doc.y);
 doc.y+=10;
 if(data.scope){drawSectionTitle(doc,M,'Assessment scope');doc.font('Helvetica').fontSize(10.5).fillColor(DOC_COLORS.textDark).text(data.scope,M,doc.y);doc.y+=10}
 drawSectionTitle(doc,M,'Assessment run');
 const runRows=[];
 if(data.filesAnalyzed!=null)runRows.push({metric:'Files analyzed',value:data.filesAnalyzed});
 if(data.rulesExecuted&&data.rulesExecuted.length)runRows.push({metric:'Rules executed',value:data.rulesExecuted.join(', ')});
 runRows.push({metric:'Total findings',value:findings.length});
 drawTable(doc,M,doc.y,[{key:'metric',label:'METRIC',w:CW*0.35,bold:true},{key:'value',label:'VALUE',w:CW*0.65,fit:true}],runRows);
 doc.y+=14;
 if(data.controlsConsidered&&data.controlsConsidered.length){
  drawSectionTitle(doc,M,'Security controls considered');
  drawTable(doc,M,doc.y,[{key:'control',label:'CONTROL',w:CW}],data.controlsConsidered.map(c=>({control:c})));
  doc.y+=14;
 }
 drawSectionTitle(doc,M,'Findings');
 if(!findings.length){doc.font('Helvetica').fontSize(10.5).fillColor(DOC_COLORS.textDark).text('No findings were generated.',M,doc.y)}
 findings.forEach(f=>{
  if(doc.y+80>doc.page.height-M)doc.addPage();
  doc.font('Helvetica-Bold').fontSize(11.5).fillColor(DOC_COLORS.textDark).text(`${f.id||''} · ${f.title||''}`,M,doc.y);
  drawTable(doc,M,doc.y+4,[{key:'field',label:'FIELD',w:CW*0.22,bold:true},{key:'value',label:'DETAIL',w:CW*0.78,fit:true,color:row=>row._color||DOC_COLORS.textDark}],[
   {field:'Status',value:f.status||'N/A'},
   {field:'Severity',value:capFirst(f.severity)||'N/A',_color:severityColor(f.severity)},
   {field:'Confidence',value:f.confidence!=null?`${f.confidence}%`:'N/A'},
   {field:'Location',value:`${f.file||'N/A'}${f.line?':'+f.line:''}`}
  ]);
  doc.y+=8;
  if(f.description){doc.font('Helvetica').fontSize(10).fillColor(DOC_COLORS.textDark).text(f.description,M,doc.y,{width:CW});doc.y+=6}
  if(f.evidence){doc.font('Courier').fontSize(8.5).fillColor('#1c2b3f').text(f.evidence,M,doc.y,{width:CW});doc.font('Helvetica');doc.y+=6}
  if(f.controls&&f.controls.length){doc.font('Helvetica-Bold').fontSize(9.5).fillColor(DOC_COLORS.textDark).text('Controls considered: ',M,doc.y,{continued:true});doc.font('Helvetica').text(f.controls.join(', '));doc.y+=4}
  if(f.recommendation){doc.font('Helvetica-Bold').fontSize(9.5).fillColor(DOC_COLORS.textDark).text('Recommendation: ',M,doc.y,{continued:true});doc.font('Helvetica').text(f.recommendation);doc.y+=4}
  doc.moveDown(0.5);
  doc.strokeColor(DOC_COLORS.border).lineWidth(0.75).moveTo(M,doc.y).lineTo(M+CW,doc.y).stroke();
  doc.y+=12;
 });
 doc.end();
}
app.post('/api/report/pdf',(req,res)=>{try{renderReportPdf(res,req.body||{})}catch(e){res.status(400).json({error:`Unable to generate PDF report: ${e.message}`})}});
function summarizeFindings(findings){
 const bySeverity={},byStatus={};
 findings.forEach(f=>{const sev=(f.severity||'unknown').toLowerCase(),st=f.status||'unknown';bySeverity[sev]=(bySeverity[sev]||0)+1;byStatus[st]=(byStatus[st]||0)+1});
 const top=findings.slice().sort((a,b)=>severityRank(a.severity)-severityRank(b.severity)||(b.confidence||0)-(a.confidence||0)).slice(0,20);
 const recommendations=[...new Set(findings.map(f=>f.recommendation).filter(Boolean))].slice(0,10);
 return {bySeverity,byStatus,top,recommendations,total:findings.length};
}
function renderSummaryPdf(res,data){
 const doc=new PDFDocument({margin:44,size:'A4',bufferPages:true});
 const filename=`${safeFilename(data.application||data.title)}-${safeFilename(data.assessmentId)}-summary.pdf`;
 res.setHeader('Content-Type','application/pdf');
 res.setHeader('Content-Disposition',`attachment; filename="${filename}"`);
 doc.pipe(res);
 const M=44,CW=doc.page.width-2*M;
 const findings=data.findings||[],s=summarizeFindings(findings);
 const dateStr=data.generatedAt?new Date(data.generatedAt).toLocaleString():new Date().toLocaleString();
 drawDocHeader(doc,M,CW,'Authorized static source analysis · executive summary',data.title||`${data.application} Security Assessment`,data.assessmentId||'N/A',dateStr);
 drawSectionTitle(doc,M,'Executive summary');
 doc.font('Helvetica').fontSize(10.5).fillColor(DOC_COLORS.textDark).text(data.summary||'No summary available.',M,doc.y);
 doc.y+=10;
 if(data.scope){drawSectionTitle(doc,M,'Scope');doc.font('Helvetica').fontSize(10.5).fillColor(DOC_COLORS.textDark).text(data.scope,M,doc.y);doc.y+=10}
 drawSectionTitle(doc,M,'Assessment run');
 const runRows=[];
 if(data.filesAnalyzed!=null)runRows.push({metric:'Files analyzed',value:data.filesAnalyzed});
 if(data.rulesExecuted&&data.rulesExecuted.length)runRows.push({metric:'Rules executed',value:data.rulesExecuted.join(', ')});
 runRows.push({metric:'Total findings',value:s.total});
 drawTable(doc,M,doc.y,[{key:'metric',label:'METRIC',w:CW*0.35,bold:true},{key:'value',label:'VALUE',w:CW*0.65,fit:true}],runRows);
 doc.y+=14;
 drawSectionTitle(doc,M,'Findings by severity');
 const sevRows=Object.entries(s.bySeverity).sort((a,b)=>severityRank(a[0])-severityRank(b[0])).map(([sev,count])=>({severity:capFirst(sev),count,percent:`${Math.round(count/s.total*100)}%`,_sev:sev}));
 drawTable(doc,M,doc.y,[{key:'severity',label:'SEVERITY',w:CW*0.4,bold:true,dot:row=>severityColor(row._sev)},{key:'count',label:'COUNT',w:CW*0.3},{key:'percent',label:'% OF TOTAL',w:CW*0.3}],sevRows);
 doc.y+=14;
 drawSectionTitle(doc,M,'Findings by status');
 const statusRows=Object.entries(s.byStatus).map(([st,count])=>({status:st,count,percent:`${Math.round(count/s.total*100)}%`}));
 drawTable(doc,M,doc.y,[{key:'status',label:'STATUS',w:CW*0.4,bold:true},{key:'count',label:'COUNT',w:CW*0.3},{key:'percent',label:'% OF TOTAL',w:CW*0.3}],statusRows);
 doc.y+=14;
 drawSectionTitle(doc,M,`Highest-priority findings (top ${s.top.length} of ${s.total})`);
 const idW=38,sevW=95,confW=62,statusW=90,fileW=CW-idW-sevW-confW-statusW-140,titleW=140;
 drawTable(doc,M,doc.y,[
  {key:'id',label:'ID',w:idW},
  {key:'title',label:'FINDING',w:titleW,fit:true},
  {key:'location',label:'FILE / LINE',w:fileW,fit:true},
  {key:'severity',label:'SEVERITY',w:sevW,dot:row=>severityColor(row._sev)},
  {key:'confidence',label:'CONFIDENCE',w:confW},
  {key:'status',label:'STATUS',w:statusW,fit:true,color:()=>DOC_COLORS.textGray}
 ],s.top.map(f=>({id:f.id,title:f.title,location:`${f.file||''}${f.line?':'+f.line:''}`,severity:capFirst(f.severity),confidence:f.confidence!=null?`${f.confidence}%`:'N/A',status:f.status,_sev:f.severity})),{emptyText:'No findings were generated.'});
 doc.y+=14;
 if(s.recommendations.length){
  drawSectionTitle(doc,M,'Key recommendations');
  s.recommendations.forEach((r,i)=>{
   if(doc.y+20>doc.page.height-M)doc.addPage();
   doc.font('Helvetica-Bold').fontSize(9.5).fillColor(DOC_COLORS.textDark).text(`${i+1}.`,M,doc.y,{continued:true,width:CW});
   doc.font('Helvetica').fontSize(9.5).text(` ${r}`);
   doc.y+=4;
  });
 }
 doc.end();
}
app.post('/api/report/summary-pdf',(req,res)=>{try{renderSummaryPdf(res,req.body||{})}catch(e){res.status(400).json({error:`Unable to generate summary PDF: ${e.message}`})}});
app.use((err,req,res,next)=>res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'ZIP archive exceeds the 100 MB analysis limit.':`Assessment upload failed: ${err.message}`}));
app.listen(5174,()=>console.log('Assessment API listening on http://127.0.0.1:5174'));
