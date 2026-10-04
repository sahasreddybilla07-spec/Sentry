import React, {useCallback, useEffect, useRef, useState} from 'react';
import { DEMO_INCIDENT } from './demoData.js';

const INITIAL_STEPS = ['','','','',''];
const INITIAL_GATES = ['✓ VERIFIED','✓ VERIFIED','✓ VERIFIED','✓ VERIFIED'];
const GATE_NAMES = ['Semgrep AST Engine','Regression Tests: 6/6 Passed','Sigstore Sign','OPA Check'];

export default function RemediationWorkspace(){
  const [progress,setProgress]=useState(0),[steps,setSteps]=useState(INITIAL_STEPS),[gates,setGates]=useState(INITIAL_GATES);
  const [pr,setPr]=useState(false),[removed,setRemoved]=useState(0),[added,setAdded]=useState(0),[note,setNote]=useState(false),[beam,setBeam]=useState(false),[complete,setComplete]=useState(false),[finalCopy,setFinalCopy]=useState(false);
  const timers=useRef([]);
  const clear=useCallback(()=>{timers.current.forEach(clearTimeout);timers.current=[]},[]);
  const later=useCallback((ms,fn)=>{timers.current.push(setTimeout(fn,ms))},[]);
  const reset=useCallback(()=>{clear();setProgress(0);setSteps(INITIAL_STEPS);setGates(INITIAL_GATES);setPr(false);setRemoved(0);setAdded(0);setNote(false);setBeam(false);setComplete(false);setFinalCopy(false)},[clear]);
  const run=useCallback(()=>{
    reset();
    const pace=1.25;
    requestAnimationFrame(()=>setProgress(100));
    later(1800*pace,()=>setSteps(['done','done','act','','']));
    later(4000*pace,()=>setSteps(['done','done','done','act','']));
    later(4500*pace,()=>setSteps(['done','done','done','done','act']));
    later(4900*pace,()=>setSteps(['done','done','done','done','done']));
    later(5200*pace,()=>setPr(true));
    later(6200*pace,()=>setRemoved(1));later(6700*pace,()=>setRemoved(2));
    later(8300*pace,()=>{setBeam(true);setRemoved(2)});
    later(8700*pace,()=>setAdded(1));later(9500*pace,()=>setAdded(2));later(10300*pace,()=>{setAdded(5);setNote(true)});
    later(10900*pace,()=>setGates(['RUNNING...','QUEUED','QUEUED','QUEUED']));
    later(11900*pace,()=>setGates(['✓ VERIFIED','RUNNING...','QUEUED','QUEUED']));
    later(12900*pace,()=>setGates(['✓ VERIFIED','✓ VERIFIED','RUNNING...','QUEUED']));
    later(13900*pace,()=>setGates(['✓ VERIFIED','✓ VERIFIED','✓ VERIFIED','RUNNING...']));
    later(14900*pace,()=>{setGates(['✓ VERIFIED','✓ VERIFIED','✓ VERIFIED','✓ VERIFIED']);setComplete(true)});
    later(15200*pace,()=>setFinalCopy(true));
  },[later,reset]);
  useEffect(()=>clear,[clear]);
  const statuses=gates.map(x=>x==='✓ VERIFIED'?'done':x==='QUEUED'?'':'run');
  return <div className="remed-page">
    <div className="remed-toolbar"><div><span className="remed-kicker">AUTONOMOUS SECURITY REMEDIATION · PROTOTYPE</span><h1>Remediation Workspace</h1><p>Illustrative patch workflow for World Monitor · synthetic source demo.</p></div><div className="remed-actions"><button onClick={run}>▶ Run remediation demo</button><button className="remed-reset" onClick={reset}>Reset</button></div></div>
    <div className="remed-nav"><div className="remed-brand"><b>SENTRY</b><span>Autonomous Security Remediation</span></div><span className="remed-nav-tab">Security Assessment</span><span className="remed-nav-tab selected">Remediation Workspace</span><span className="remed-project">Project <b>{'koala73/worldmonitor'}</b></span><span className={`remed-badge ${complete?'complete':''}`}><i/>{complete?'DEMO COMPLETE':'DEMO READY'}</span></div>
    <div className="remed-content">
      <section className={`remed-stage ${complete?'passed':''}`}>
        <div className={`remed-layer ${pr?'hidden':''}`}>
          <div className="remed-eyebrow">△ &nbsp; SYNTHETIC DEMO · NOT A VERIFIED REPOSITORY FINDING</div>
          <div className="remed-vuln"><h2>CVE-2026-X: Stored XSS via Unsafe URI Schemes in Advisory Links</h2><div className="remed-chips"><span className="critical">Severity <b>HIGH · CVSS 8.5</b></span><span>Target <b>src/components/SecurityAdvisoriesPanel.ts</b></span><span className="auto">Status <b>Illustrative patch</b></span></div></div>
          <div className="remed-progress-line"><span><em>Semgrep AST Engine</em> — Synthesizing Patch...</span><b>{progress}%</b></div><div className="remed-progress"><i style={{width:`${progress}%`}}/></div>
          <div className="remed-steps">{['Vulnerability Located','Data Flow Analyzed','Patch Being Synthesized','Security Validation','Pull Request Generation'].map((x,i)=><span className={steps[i]} key={x}><i>{steps[i]==='done'?'✓':steps[i]==='act'?'●':'○'}</i>{x}</span>)}</div>
        </div>
        <div className={`remed-layer ${pr?'':'hidden'}`}>
          <div className="pr-header"><span className="pr-icon">✓</span><h2>Sentry Bot prepared an example patch <small>{DEMO_INCIDENT.id}</small></h2><span className="remed-badge complete"><i/>EXAMPLE PATCH</span></div>
          <div className="pr-title">example: require authentication and limit ship-tracking requests</div>
          <div className="pr-meta"><b><i className="bot-icon">S</i> Sentry Bot</b><span className="purple-pill">Automated Security Remediation</span><span>Example diff · no file changed</span><span><strong className="add">+12</strong> &nbsp;<strong className="del">−8</strong></span><code>{`demo/${DEMO_INCIDENT.id} → review only`}</code><span>illustrative preview · no repository change</span></div>
        </div>
      </section>
      <section className="remed-diff">
        <div className="diff-head"><b>SecurityAdvisoriesPanel.ts · sanitize advisory links</b><span>+5 &nbsp; −2</span><small>Example patch</small></div><div className="diff-hunk">@@ src/components/SecurityAdvisoriesPanel.ts · validate advisory URI schemes</div>
        <div className="diff-code">
          {[['101'," import { escapeHtml, unsafeRawHtml } from '@/utils/sanitize';"],['102',' <a href="${escapeHtml(a.link)}" target="_blank" rel="noopener" class="sa-title">${escapeHtml(a.title)}</a>']].map(([n,t],i)=><div key={n} className={`diff-row removed ${removed>i?'show':''}`}><span>{n}</span><span></span><b>−</b><code>{t}</code></div>)}
          {[['101'," import { escapeHtml, safeUrlAttr, unsafeRawHtml } from '@/utils/sanitize';"],['102',' const href = safeUrlAttr(a.link).toString();'],['103',' const titleMarkup = href'],['104','   ? `<a href="${href}" target="_blank" rel="noopener" class="sa-title">${escapeHtml(a.title)}</a>`'],['105','   : `<span class="sa-title sa-title-plain">${escapeHtml(a.title)}</span>`;']].map(([n,t],i)=><div key={n} className={`diff-row inserted ${added>i?'show':''}`}><span></span><span>{n}</span><b>+</b><code>{t}</code></div>)}
          <div className={`diff-note ${note?'show':''}`}><b>✓ Unsafe URI schemes rejected before rendering</b><span>Illustrative diff only · no upstream file changed</span></div>{beam&&<div className="diff-beam"/>}
        </div>
      </section>
      <section className={`remed-gates ${complete?'ok':''}`}>
        <div className="gates-heading">AUTOMATED SECURITY GATES <span>Illustrative checks · no connected production CI/CD</span></div>
        <div className="gate-pipeline">{GATE_NAMES.map((name,i)=><React.Fragment key={name}><div className={`remed-gate ${statuses[i]}`}><i>{statuses[i]==='done'?'✓':statuses[i]==='run'?'◌':i===0?'⌕':i===1?'◇':'▤'}</i><div><b>{name}</b><small>{gates[i]}</small></div></div>{i<GATE_NAMES.length-1&&<span className={`gate-arrow ${statuses[i]==='done'?'on':''}`}>→</span>}</React.Fragment>)}</div>
        <div className={`remed-final ${complete?'on':''}`}><b>{finalCopy?'DEMO COMPLETE — EXAMPLE CHECKS PASSED ✓':complete?'EXAMPLE CHECKS PASSED':'AWAITING VERIFICATION'}</b><span>{finalCopy?'Illustrative checks · no external CI connected':'Example only · no repository change made'}</span></div>
      </section>
    </div>
  </div>
}
