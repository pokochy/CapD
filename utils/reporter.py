"""
utils/reporter.py
──────────────────
스캔 결과를 HTML / JSON 보고서로 변환.

두 가지 용도로 사용:
  1. CLI 모드 — generate_html() / save_json() 직접 호출
  2. API 모드 — generate_html_from_job() 로 ScanJob ORM 객체를 HTML로 변환
                (GET /api/reports/{job_id}/html 엔드포인트에서 사용)
"""
from __future__ import annotations

import json
import os
from datetime import datetime

# ── HTML 템플릿 (인라인 CSS + JS, 다크모드, 검색, PDF 저장) ──────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>취약점 스캔 보고서</title>
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{
    --bg:#f5f5f4;--surface:#fff;--surface2:#f7f6f3;
    --border:rgba(0,0,0,.1);--text:#1c1c1a;--muted:#73726c;--radius:10px;
    --c-critical:#E24B4A;--c-critical-bg:#FCEBEB;--c-critical-tx:#791F1F;
    --c-high:#EF9F27;--c-high-bg:#FAEEDA;--c-high-tx:#633806;
    --c-medium:#378ADD;--c-medium-bg:#E6F1FB;--c-medium-tx:#0C447C;
    --c-low:#1D9E75;--c-low-bg:#E1F5EE;--c-low-tx:#085041;
    --c-info:#888780;--c-info-bg:#F1EFE8;--c-info-tx:#444441;
    --c-ok:#1D9E75;--c-ok-bg:#E1F5EE;--c-ok-tx:#085041;
    --c-miss:#E24B4A;--c-miss-bg:#FCEBEB;--c-miss-tx:#791F1F;
  }
  @media(prefers-color-scheme:dark){
    :root{--bg:#1a1a18;--surface:#242422;--surface2:#2c2c2a;
      --border:rgba(255,255,255,.1);--text:#e8e6de;--muted:#888780;
      --c-critical-bg:#501313;--c-critical-tx:#F09595;
      --c-high-bg:#412402;--c-high-tx:#FAC775;
      --c-medium-bg:#042C53;--c-medium-tx:#85B7EB;
      --c-low-bg:#04342C;--c-low-tx:#5DCAA5;
      --c-info-bg:#2C2C2A;--c-info-tx:#B4B2A9;
      --c-ok-bg:#04342C;--c-ok-tx:#5DCAA5;
      --c-miss-bg:#501313;--c-miss-tx:#F09595;
    }
  }
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
    background:var(--bg);color:var(--text);font-size:14px;line-height:1.6;padding:32px 16px;}
  .wrap{max-width:860px;margin:0 auto;}
  .header{margin-bottom:28px;}
  .header h1{font-size:20px;font-weight:600;margin-bottom:4px;}
  .meta{font-size:12px;color:var(--muted);display:flex;gap:12px;flex-wrap:wrap;}
  .meta span::before{content:"·";margin-right:8px;}
  .meta span:first-child::before{display:none;}
  .card{background:var(--surface);border:0.5px solid var(--border);
    border-radius:var(--radius);padding:18px 20px;margin-bottom:14px;}
  .card-title{font-size:11px;font-weight:600;margin-bottom:14px;color:var(--muted);
    text-transform:uppercase;letter-spacing:.05em;}
  .stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px;}
  @media(max-width:560px){.stat-grid{grid-template-columns:repeat(2,1fr);}}
  .stat-card{background:var(--surface);border:0.5px solid var(--border);
    border-radius:var(--radius);padding:14px 16px;text-align:center;}
  .stat-label{font-size:11px;color:var(--muted);margin-bottom:4px;}
  .stat-val{font-size:26px;font-weight:600;}
  .stat-val.danger{color:var(--c-critical);}
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px;}
  @media(max-width:600px){.two-col{grid-template-columns:1fr;}}
  .sev-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
  .sev-label{font-size:12px;width:58px;color:var(--muted);}
  .sev-track{flex:1;background:var(--surface2);border-radius:4px;height:10px;overflow:hidden;}
  .sev-fill{height:10px;border-radius:4px;}
  .sev-count{font-size:12px;font-weight:600;min-width:20px;text-align:right;}
  .badge{display:inline-flex;align-items:center;padding:3px 9px;
    border-radius:5px;font-size:11px;font-weight:500;line-height:1.4;}
  .badge-wrap{display:flex;flex-wrap:wrap;gap:6px;}
  .check-list{display:flex;flex-direction:column;gap:7px;margin-top:4px;}
  .check-item{display:flex;align-items:center;gap:8px;font-size:12px;}
  .check-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
  .dot-ok{background:var(--c-ok);}
  .dot-miss{background:var(--c-miss);}
  .toolbar{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap;align-items:center;}
  .tabs{display:flex;gap:6px;flex-wrap:wrap;}
  .tab-btn{padding:5px 13px;font-size:12px;font-weight:500;border-radius:6px;
    border:0.5px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;}
  .tab-btn.active{background:var(--surface2);color:var(--text);}
  .search-input{flex:1;min-width:180px;padding:6px 12px;font-size:13px;
    border:0.5px solid var(--border);border-radius:8px;
    background:var(--surface2);color:var(--text);}
  .search-input::placeholder{color:var(--muted);}
  .finding{border-left:3px solid #ccc;padding:12px 14px;margin-bottom:8px;
    border-radius:0 8px 8px 0;background:var(--surface2);cursor:pointer;}
  .finding:hover{opacity:.82;}
  .f-head{display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;}
  .f-name{font-size:13px;font-weight:600;}
  .f-meta{font-size:12px;color:var(--muted);}
  .f-detail{display:none;margin-top:10px;padding-top:10px;
    border-top:0.5px solid var(--border);font-size:12px;}
  .f-detail.open{display:block;}
  .f-row{display:flex;gap:8px;margin-bottom:5px;}
  .f-key{color:var(--muted);min-width:72px;}
  .f-val{word-break:break-all;}
  .highlight{background:#fff176;color:#1c1c1a;border-radius:2px;padding:0 1px;}
  code{font-family:"SFMono-Regular",Consolas,monospace;
    background:var(--surface2);padding:1px 5px;border-radius:4px;font-size:11px;}
  .empty{text-align:center;padding:32px;color:var(--muted);font-size:13px;}
  .result-count{font-size:12px;color:var(--muted);margin-bottom:10px;}
  .footer{text-align:center;font-size:11px;color:var(--muted);margin-top:28px;}
  .btn-pdf{padding:5px 13px;font-size:12px;font-weight:500;border-radius:6px;
    border:0.5px solid var(--border);background:transparent;color:var(--muted);
    cursor:pointer;margin-left:auto;}
  .btn-pdf:hover{background:var(--surface2);}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>취약점 스캔 보고서</h1>
    <div class="meta"><span id="meta-url"></span><span id="meta-time"></span></div>
  </div>

  <div class="stat-grid">
    <div class="stat-card"><div class="stat-label">크롤링 페이지</div><div class="stat-val" id="s-pages">0</div></div>
    <div class="stat-card"><div class="stat-label">발견 취약점</div><div class="stat-val danger" id="s-vuln">0</div></div>
    <div class="stat-card"><div class="stat-label">고위험 (C+H)</div><div class="stat-val danger" id="s-high">0</div></div>
    <div class="stat-card"><div class="stat-label">누락 보안 헤더</div><div class="stat-val danger" id="s-headers">0</div></div>
  </div>

  <div class="two-col">
    <div class="card">
      <div class="card-title">심각도 분포</div>
      <div id="sev-bars"></div>
    </div>
    <div class="card">
      <div class="card-title">기술 스택</div>
      <div class="badge-wrap" id="stack-badges" style="margin-bottom:14px"></div>
      <div class="card-title" style="margin-top:8px">보안 헤더</div>
      <div class="check-list" id="header-checks"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-title">취약점 목록</div>
    <div class="toolbar">
      <div class="tabs" id="tabs"></div>
      <input class="search-input" id="search" type="text"
             placeholder="🔍  URL · 파라미터 · 페이로드 검색..."
             oninput="applyFilter()">
      <button class="btn-pdf" onclick="window.print()">PDF 저장</button>
    </div>
    <div class="result-count" id="result-count"></div>
    <div id="finding-list"></div>
  </div>

  <div class="footer">Web Vulnerability Scanner v2.0 &nbsp;·&nbsp; <span id="footer-time"></span></div>
</div>

<script>
const DATA = __REPORT_DATA__;
const SEV_COLOR={critical:"var(--c-critical)",high:"var(--c-high)",medium:"var(--c-medium)",low:"var(--c-low)",info:"var(--c-info)"};
const SEV_ORDER={critical:0,high:1,medium:2,low:3,info:4};
function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");}
function bSty(s){const k=(s||"info").toLowerCase();return `background:var(--c-${k}-bg);color:var(--c-${k}-tx);`;}
function highlight(text, query) {
  if (!query) return esc(text);
  const escaped = esc(text);
  const escapedQ = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return escaped.replace(new RegExp(escapedQ, 'gi'), m => `<span class="highlight">${m}</span>`);
}
let currentSev = "all";
function init(){
  const findings=(DATA.findings||[]).sort((a,b)=>(SEV_ORDER[a.severity]||9)-(SEV_ORDER[b.severity]||9));
  const fp=DATA.fingerprint||{};
  const now=new Date(DATA.generated_at||Date.now());
  document.getElementById("meta-url").textContent=DATA.target_url||fp.url||"—";
  document.getElementById("meta-time").textContent=now.toLocaleString("ko-KR");
  document.getElementById("footer-time").textContent=now.toLocaleString("ko-KR");
  document.getElementById("s-pages").textContent=DATA.pages_count||0;
  document.getElementById("s-vuln").textContent=findings.length;
  document.getElementById("s-high").textContent=findings.filter(f=>["critical","high"].includes(f.severity)).length;
  document.getElementById("s-headers").textContent=(fp.missing_security||[]).length;
  const dist={};
  findings.forEach(f=>{const s=f.severity||"info";dist[s]=(dist[s]||0)+1;});
  const total=findings.length||1;
  let bHtml="";
  ["critical","high","medium","low","info"].forEach(s=>{
    if(!dist[s])return;
    const pct=Math.round(dist[s]/total*100);
    bHtml+=`<div class="sev-row"><span class="sev-label">${s.charAt(0).toUpperCase()+s.slice(1)}</span>
      <div class="sev-track"><div class="sev-fill" style="width:${pct}%;background:${SEV_COLOR[s]}"></div></div>
      <span class="sev-count">${dist[s]}</span></div>`;
  });
  document.getElementById("sev-bars").innerHTML=bHtml||'<span style="font-size:12px;color:var(--muted)">발견된 취약점 없음</span>';
  let sHtml="";
  if(fp.webserver){const vv=(fp.validation||[]).find(v=>v.tech===fp.webserver&&v.status==="vulnerable");
    const sty=vv?"background:var(--c-critical-bg);color:var(--c-critical-tx);":"background:var(--c-ok-bg);color:var(--c-ok-tx);";
    sHtml+=`<span class="badge" style="${sty}">${esc(fp.webserver)} ${esc(fp.webserver_version||"")}${vv?" ⚠":""}</span>`;}
  if(fp.language){const vv=(fp.validation||[]).find(v=>v.tech===fp.language&&v.status==="vulnerable");
    const sty=vv?"background:var(--c-critical-bg);color:var(--c-critical-tx);":"background:var(--c-ok-bg);color:var(--c-ok-tx);";
    sHtml+=`<span class="badge" style="${sty}">${esc(fp.language)} ${esc(fp.language_version||"")}${vv?" ⚠":""}</span>`;}
  if(fp.os)sHtml+=`<span class="badge" style="background:var(--c-info-bg);color:var(--c-info-tx);">${esc(fp.os)}</span>`;
  (fp.framework||[]).forEach(fw=>{sHtml+=`<span class="badge" style="background:var(--c-medium-bg);color:var(--c-medium-tx);">${esc(fw)}</span>`;});
  (fp.technologies||[]).forEach(t=>{if(!["nginx","apache","iis","express","flask","django","spring","rails","laravel","wordpress"].includes(t))
    sHtml+=`<span class="badge" style="background:var(--c-info-bg);color:var(--c-info-tx);">${esc(t)}</span>`;});
  document.getElementById("stack-badges").innerHTML=sHtml||'<span style="font-size:12px;color:var(--muted)">정보 없음</span>';
  let hHtml="";
  (fp.security_headers||[]).forEach(h=>{hHtml+=`<div class="check-item"><div class="check-dot dot-ok"></div><span>${esc(h)}</span></div>`;});
  (fp.missing_security||[]).forEach(h=>{hHtml+=`<div class="check-item"><div class="check-dot dot-miss"></div><span style="color:var(--c-miss-tx)">${esc(h)} <span style="color:var(--muted)">(누락)</span></span></div>`;});
  document.getElementById("header-checks").innerHTML=hHtml||'<span style="font-size:12px;color:var(--muted)">정보 없음</span>';
  const allSevs=["all",...["critical","high","medium","low","info"].filter(s=>dist[s])];
  let tHtml="";
  allSevs.forEach(s=>{
    const cnt=s==="all"?findings.length:(dist[s]||0);
    const lbl=s==="all"?"전체":s.charAt(0).toUpperCase()+s.slice(1);
    tHtml+=`<button class="tab-btn${s==="all"?" active":""}" data-sev="${s}" onclick="selectTab(this)">${lbl} ${cnt}</button>`;
  });
  document.getElementById("tabs").innerHTML=tHtml;
  renderList(findings);
}
function renderList(findings){
  const query=document.getElementById("search").value.toLowerCase().trim();
  const list=findings.filter(f=>{
    if(currentSev!=="all"&&f.severity!==currentSev)return false;
    if(!query)return true;
    return (f.matched_at||f.url||"").toLowerCase().includes(query)
        || (f.inject_param||"").toLowerCase().includes(query)
        || (f.payload||"").toLowerCase().includes(query)
        || (f.vulnerability||f.vuln_name||"").toLowerCase().includes(query)
        || (f.evidence||"").toLowerCase().includes(query);
  });
  document.getElementById("result-count").textContent=query
    ?`검색 결과: ${list.length}건 / 전체 ${findings.length}건`:`총 ${list.length}건`;
  if(!list.length){
    document.getElementById("finding-list").innerHTML=
      `<div class="empty">${query?`"${esc(query)}" 에 대한 결과가 없습니다.`:"발견된 취약점이 없습니다."}</div>`;
    return;
  }
  let html="";
  list.forEach(f=>{
    const s=(f.severity||"info").toLowerCase();
    const name=f.vulnerability||f.vuln_name||"Unknown";
    const url=f.matched_at||f.url||"";
    const param=f.inject_param||(f.extra&&f.extra.param)||"";
    const group=f.payload_group||f.position||"";
    const strategy=f.strategy||(f.extra&&f.extra.strategy)||"";
    html+=`<div class="finding" style="border-left-color:${SEV_COLOR[s]||"var(--c-info)"}" onclick="toggleDetail(this)">
      <div class="f-head"><span class="badge" style="${bSty(s)}">${s.charAt(0).toUpperCase()+s.slice(1)}</span>
        <span class="f-name">${highlight(name, query)}</span>
        ${group?`<span class="badge" style="background:var(--c-info-bg);color:var(--c-info-tx);">${esc(group)}</span>`:""}
      </div>
      <div class="f-meta">${highlight(url, query)}</div>
      <div class="f-detail">
        <div class="f-row"><span class="f-key">페이로드</span><span class="f-val"><code>${highlight(f.payload, query)}</code></span></div>
        ${param?`<div class="f-row"><span class="f-key">파라미터</span><span class="f-val"><code>${esc(param)}</code></span></div>`:""}
        ${f.evidence?`<div class="f-row"><span class="f-key">증거</span><span class="f-val"><code>${highlight(f.evidence, query)}</code></span></div>`:""}
        ${strategy?`<div class="f-row"><span class="f-key">전략</span><span class="f-val">${esc(strategy)}</span></div>`:""}
        ${f.template_id?`<div class="f-row"><span class="f-key">템플릿</span><span class="f-val">${esc(f.template_id)}</span></div>`:""}
      </div>
    </div>`;
  });
  document.getElementById("finding-list").innerHTML=html;
}
function selectTab(btn){
  document.querySelectorAll(".tab-btn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  currentSev=btn.dataset.sev;
  applyFilter();
}
function applyFilter(){
  const findings=(DATA.findings||[]).sort((a,b)=>(SEV_ORDER[a.severity]||9)-(SEV_ORDER[b.severity]||9));
  renderList(findings);
}
function toggleDetail(el){el.querySelector(".f-detail").classList.toggle("open");}
init();
</script>
</body>
</html>"""


def _render_html(report_data: dict) -> str:
    json_str = json.dumps(report_data, ensure_ascii=False, default=str).replace("</", "<\\/")
    return _HTML_TEMPLATE.replace("__REPORT_DATA__", json_str)


# ── API 모드: ScanJob ORM 객체 → HTML ────────────────────────────────────────

def generate_html_from_job(job, fingerprint: dict | None = None) -> str:
    """
    FastAPI 엔드포인트용. ScanJob ORM 인스턴스를 받아 HTML 문자열 반환.

    job.results 는 eager-loaded된 ScanResult 리스트여야 한다.
    fingerprint 는 worker/tasks.py가 저장한 핑거프린트 딕셔너리 (job.fingerprint_result).
    """
    findings = [
        {
            "vuln_name":    r.vuln_name,
            "vulnerability": r.vuln_name,
            "severity":     r.severity,
            "matched_at":   r.matched_at,
            "payload":      r.payload,
            "payload_group": r.payload_group,
            "template_id":  r.template_id,
            "evidence":     r.evidence,
            "extra":        r.extra or {},
            "strategy":     (r.extra or {}).get("strategy"),
        }
        for r in (job.results or [])
    ]

    report_data = {
        "generated_at":   datetime.utcnow().isoformat(),
        "target_url":     job.target_url,
        "job_id":         job.id,
        "status":         job.status,
        "fingerprint":    fingerprint or {},
        "pages_count":    0,
        "total_findings": len(findings),
        "findings":       findings,
    }
    return _render_html(report_data)


# ── CLI 모드: dict 리스트 → HTML / JSON ────────────────────────────────────────

def make_report_dir(base: str = "reports") -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(base, f"scan_{timestamp}")
    os.makedirs(path, exist_ok=True)
    return path


def generate_html(
    findings: list[dict],
    fp_result: dict | None = None,
    pages_count: int = 0,
    target_url: str = "",
    path: str = "scan_report.html",
) -> None:
    """CLI 파이프라인용. findings는 dict 리스트."""
    report_data = {
        "generated_at":   datetime.now().isoformat(),
        "target_url":     target_url,
        "fingerprint":    fp_result or {},
        "pages_count":    pages_count,
        "total_findings": len(findings),
        "findings":       findings,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(_render_html(report_data))
    print(f"  HTML 저장: {path}")


def save_json(
    findings: list[dict],
    fp_result: dict | None = None,
    pages_count: int = 0,
    target_url: str = "",
    path: str = "scan_report.json",
) -> dict:
    """CLI 파이프라인용."""
    data = {
        "generated_at":   datetime.now().isoformat(),
        "target_url":     target_url,
        "fingerprint":    fp_result,
        "pages_count":    pages_count,
        "total_findings": len(findings),
        "findings":       findings,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    print(f"  JSON 저장: {path}")
    return data
