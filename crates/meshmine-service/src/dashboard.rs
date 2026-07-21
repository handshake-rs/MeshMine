use meshmine_gateway::GatewayStatus;
use serde::{Deserialize, Serialize};

use crate::{ServiceEventRecord, SupervisorSnapshot};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatusView {
    pub current_job_id: Option<String>,
    pub current_assignment_sequence: Option<u64>,
    pub current_issued_ms: Option<u64>,
    pub current_assignment_end_ms: Option<u64>,
    pub current_submission_end_ms: Option<u64>,
    pub retained_jobs: usize,
    pub pending_captures: usize,
    pub retiring_assignments: usize,
    pub queued_events: usize,
    pub dropped_events: u64,
}

impl From<GatewayStatus> for GatewayStatusView {
    fn from(value: GatewayStatus) -> Self {
        Self {
            current_job_id: value.current_job_id,
            current_assignment_sequence: value.current_assignment_sequence,
            current_issued_ms: value.current_issued_ms,
            current_assignment_end_ms: value.current_assignment_end_ms,
            current_submission_end_ms: value.current_submission_end_ms,
            retained_jobs: value.retained_jobs,
            pending_captures: value.pending_captures,
            retiring_assignments: value.retiring_assignments,
            queued_events: value.queued_events,
            dropped_events: value.dropped_events,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCountersView {
    pub accepted_captures: u64,
    pub rejected_submissions: u64,
    pub job_issues: u64,
    pub job_cancellations: u64,
    pub failovers: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorSnapshot {
    pub generated_at_ms: u64,
    pub supervisor: SupervisorSnapshot,
    pub gateway: GatewayStatusView,
    pub gateway_listen: String,
    pub dashboard_listen: String,
    pub active_connections: usize,
    pub authorization_failures: u16,
    pub gateway_listener_alive: bool,
    pub dashboard_listener_alive: bool,
    pub credentials_available: bool,
    pub core_link_connected: bool,
    pub core_link_last_message_ms: Option<u64>,
    pub active_bundle_id: Option<String>,
    pub pending_bundle_id: Option<String>,
    pub assignment_drain_pending: bool,
    pub counters: OperatorCountersView,
    pub fallback_endpoint: Option<String>,
    pub production_eligible: bool,
    pub authority_note: String,
    pub events: Vec<ServiceEventRecord>,
}

pub fn dashboard_html() -> &'static str {
    r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MeshMine Operator</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101216;color:#eef2f7}
body{margin:0;padding:24px;max-width:1200px;margin-inline:auto}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.card{background:#191d24;border:1px solid #2a303a;border-radius:12px;padding:16px}.label{color:#9ba7b7;font-size:.82rem}.value{font-size:1.45rem;font-weight:650;margin-top:4px;overflow-wrap:anywhere}.ok{color:#62d98b}.warn{color:#ffcc66}.bad{color:#ff7b72}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px;border-bottom:1px solid #2a303a;font-size:.9rem}code{font-size:.82rem}h1{margin-top:0}#error{display:none}
</style>
</head>
<body>
<h1>MeshMine Operator</h1><p id="error" class="bad"></p>
<div class="grid">
<div class="card"><div class="label">Mode</div><div id="mode" class="value">Loading</div></div>
<div class="card"><div class="label">Current job</div><div id="job" class="value">—</div></div>
<div class="card"><div class="label">ASIC connections</div><div id="connections" class="value">0</div></div>
<div class="card"><div class="label">Pending captures</div><div id="captures" class="value">0</div></div>
<div class="card"><div class="label">Gateway</div><div id="gateway" class="value">—</div></div>
<div class="card"><div class="label">Fallback</div><div id="fallback" class="value">—</div></div>
<div class="card"><div class="label">Accepted captures</div><div id="accepted" class="value">0</div></div>
<div class="card"><div class="label">Rejected submissions</div><div id="rejected" class="value">0</div></div>
<div class="card"><div class="label">Listener health</div><div id="listeners" class="value">—</div></div>
<div class="card"><div class="label">Core link</div><div id="corelink" class="value">—</div></div>
<div class="card"><div class="label">Active bundle</div><div id="bundle" class="value">—</div></div>
<div class="card"><div class="label">Assignment drain</div><div id="drain" class="value">—</div></div>
</div>
<div class="card" style="margin-top:14px"><div class="label">Authority boundary</div><p id="authority"></p></div>
<div class="card" style="margin-top:14px"><h2>Recent events</h2><table><thead><tr><th>Time</th><th>Kind</th><th>Message</th></tr></thead><tbody id="events"></tbody></table></div>
<script>
const text=(id,v)=>document.getElementById(id).textContent=v;
const esc=v=>String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function refresh(){try{const r=await fetch('/api/v1/status',{cache:'no-store'});if(!r.ok)throw new Error('HTTP '+r.status);const s=await r.json();const m=s.supervisor.mode;text('mode',m+' / '+s.supervisor.reason);document.getElementById('mode').className='value '+(m==='mining'?'ok':m==='fallback'?'bad':'warn');text('job',s.gateway.current_job_id||'none');text('connections',s.active_connections);text('captures',s.gateway.pending_captures);text('gateway',s.gateway_listen);text('fallback',s.fallback_endpoint||'not configured');text('accepted',s.counters.accepted_captures);text('rejected',s.counters.rejected_submissions);text('listeners',(s.gateway_listener_alive?'gateway up':'gateway down')+' / '+(s.dashboard_listener_alive?'dashboard up':'dashboard down'));text('corelink',s.core_link_connected?'connected':'disconnected');text('bundle',s.active_bundle_id||'none');text('drain',s.assignment_drain_pending?'pending':'none');text('authority',s.authority_note);const rows=s.events.slice().reverse().map(e=>`<tr><td>${esc(new Date(e.observed_at_ms).toLocaleString())}</td><td>${esc(e.kind)}</td><td>${esc(e.message)}</td></tr>`).join('');document.getElementById('events').innerHTML=rows;document.getElementById('error').style.display='none'}catch(e){const x=document.getElementById('error');x.textContent=e.message;x.style.display='block'}}
refresh();setInterval(refresh,2000);
</script>
</body></html>"#
}

pub fn json_response(snapshot: &OperatorSnapshot) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(snapshot)
}
