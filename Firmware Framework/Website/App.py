#!/usr/bin/env python3
"""
Behemoth web interface.
"""
import glob
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from flask import Flask, Response, jsonify, render_template_string, request, send_file, stream_with_context

# ---------------------------------------------------------------------------
# Framework layout
# ---------------------------------------------------------------------------

WEBSITE_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(WEBSITE_DIR)

BUILD_DIR = os.path.join(BASE, "Build")
EVOLVE_DIR = os.path.join(BASE, "Evolve")
HUNT_DIR = os.path.join(BASE, "Hunt")
GDT_DIR = os.path.join(BUILD_DIR, "GDT")

# Images lives next to "Firmware Framework".
FRAMEWORK_PARENT = os.path.dirname(BASE)
LOGO_DIR = os.path.join(FRAMEWORK_PARENT, "Images", "Logos")

RETYPE_SCRIPTS = [
	"ScriptEvolve02BehemothRetyper.java",
]

HUNT_SCRIPTS = [
	"ScriptHunt00BehemothVariableHunter.java",
	"ScriptHunt01BehemothShellCommandHunter.java",
	"ScriptHunt02BehemothCustomImageLoadHunter.java",
]

TIMEOUT = 900
REPORT_DIR = os.path.expanduser("~")


def find_headless():
	name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
	hits = glob.glob(
		os.path.join(GDT_DIR, "**", "support", name),
		recursive=True,
	)
	return hits[0] if hits else ""


def find_logo():
	if not os.path.isdir(LOGO_DIR):
		return None

	preferred = (
		"Behemoth.png",
		"behemoth.png",
		"Behemoth-Logo.png",
		"behemoth-logo.png",
		"logo.png",
	)
	for name in preferred:
		path = os.path.join(LOGO_DIR, name)
		if os.path.isfile(path):
			return path

	pngs = sorted(glob.glob(os.path.join(LOGO_DIR, "*.png")))
	return pngs[0] if pngs else None


HEADLESS = find_headless()
SCRIPTS = EVOLVE_DIR + ";" + HUNT_DIR
LOGO_PATH = find_logo()

# PE machine type -> arch tag
_MACHINE = {0x8664: "x64", 0x14c: "ia32", 0xaa64: "aarch64", 0x1c0: "arm"}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4, "info": 5}

app = Flask(__name__)


def detect_arch(path):
	"""Read the PE COFF machine field to tell x64 from ia32."""
	try:
		with open(path, "rb") as f:
			head = f.read(0x400)
		if head[:2] != b"MZ":
			return None
		e = int.from_bytes(head[0x3c:0x40], "little")
		if e + 6 > len(head):
			with open(path, "rb") as f:
				head = f.read(e + 6)
		if head[e:e + 4] != b"PE\x00\x00":
			return None
		return _MACHINE.get(int.from_bytes(head[e + 4:e + 6], "little"))
	except Exception:
		return None


def _find_under(base, name):
	"""base/name, else base/*/name (one level deep — covers GDT/GUIDs/ etc.)."""
	if not base:
		return None
	p = os.path.join(base, name)
	if os.path.isfile(p):
		return p
	hits = glob.glob(os.path.join(base, "*", name))
	return hits[0] if hits else None


def choose_gdt(arch):
	"""Return the Behemoth type archive matching the sample architecture."""
	fname = "Behemoth_IA32.gdt" if arch == "ia32" else "Behemoth_X64.gdt"
	return _find_under(GDT_DIR, fname)


def _build_command(args):
	"""Return a value for Popen. On Windows a .bat must go through cmd, and the
	whole command is wrapped as  cmd /c "..."  so cmd strips only that outer pair
	and inner-quoted tokens (like the ;-joined -scriptPath) survive intact."""
	if os.name == "nt" and str(args[0]).lower().endswith((".bat", ".cmd")):
		def q(a):
			a = str(a)
			return '"%s"' % a if (a == "" or any(c in a for c in ' \t;,&|()<>^')) else a
		return 'cmd /c "' + " ".join(q(a) for a in args) + '"'
	return args


def stream_headless(efi_path, job_dir, gdt_path, arch):
	"""Run analyzeHeadless and yield ('line', text) per stdout line, then ('rc', code)."""
	proj = "gh_" + uuid.uuid4().hex[:8]
	args = [HEADLESS, job_dir, proj, "-import", efi_path,
			"-scriptPath", SCRIPTS, "-deleteProject",
			"-analysisTimeoutPerFile", str(TIMEOUT)]
	for s in RETYPE_SCRIPTS + HUNT_SCRIPTS:               # Evolve then Hunt, NO args
		args += ["-postScript", s]
	env = dict(os.environ)
	if gdt_path:
		env["BEHEMOTH_GDT"] = gdt_path                    # retype scripts read this to open the archive
	if arch:
		env["BEHEMOTH_ARCH"] = "IA32" if arch == "ia32" else "X64"
	guids = _find_under(GDT_DIR, "Behemoth_GUIDs.ini")
	if guids and os.path.isfile(guids):
		env["BEHEMOTH_GUIDS"] = guids                     # GUID DB path (avoids askFile in headless)

	proc = subprocess.Popen(_build_command(args), stdout=subprocess.PIPE,
							stderr=subprocess.STDOUT, text=True, bufsize=1, env=env)
	try:
		for line in proc.stdout:
			yield ("line", line.rstrip("\r\n"))
		proc.wait(timeout=TIMEOUT + 120)
	except subprocess.TimeoutExpired:
		proc.kill()
		yield ("line", "[timeout] analyzeHeadless killed after %ss" % (TIMEOUT + 120))
	except Exception as e:
		yield ("line", "[error] " + str(e))
	yield ("rc", proc.returncode)


def normalize(f):
	"""Accept name|title|id and clamp severity."""
	name = f.get("name") or f.get("title") or f.get("id") or "finding"
	sev = str(f.get("severity", "info")).lower()
	if sev not in SEV_ORDER:
		sev = "info"
	out = {"severity": sev, "name": name,
		"description": f.get("description", "")}
	if f.get("location"):
		out["location"] = f["location"]
	if f.get("detector"):
		out["detector"] = f["detector"]
	return out


def collect(program_name, efi_path):
	"""Merge every <program_name>.*.json the detectors wrote."""
	findings, produced = [], []
	pattern = os.path.join(REPORT_DIR, glob.escape(program_name) + ".*.json")
	for jf in sorted(glob.glob(pattern)):
		produced.append(os.path.basename(jf))
		try:
			data = json.load(open(jf))
		except Exception as e:
			findings.append({"severity": "info", "name": "Parse error: " + os.path.basename(jf),
							"description": str(e), "detector": "backend"})
			continue
		raw = data.get("findings", data) if isinstance(data, dict) else data
		if isinstance(raw, dict):
			raw = [raw]
		for item in (raw or []):
			if isinstance(item, dict):
				item.setdefault("detector", data.get("detector") if isinstance(data, dict) else None)
				findings.append(normalize(item))

	findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))
	summary = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
	with open(efi_path, "rb") as fh:
		sha = hashlib.sha256(fh.read()).hexdigest()
	return {
		"sample": {"filename": program_name, "sha256": sha, "size": os.path.getsize(efi_path)},
		"analyzed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
		"summary": summary,
		"findings": findings,
		"_reports": produced,
	}


def cleanup_reports(program_name):
	for ext in (".*.json", ".*.txt"):
		for p in glob.glob(os.path.join(REPORT_DIR, glob.escape(program_name) + ext)):
			try:
				os.remove(p)
			except OSError:
				pass


@app.route("/analyze", methods=["POST"])
def analyze():
	if "file" not in request.files or not request.files["file"].filename:
		return jsonify({"error": "no file"}), 400
	up = request.files["file"]
	orig_name = up.filename
	job = tempfile.mkdtemp(prefix="efi_")
	program_name = "sample_%s.efi" % uuid.uuid4().hex[:8]
	efi = os.path.join(job, program_name)
	up.save(efi)

	def gen():
		def ev(d):
			return json.dumps(d) + "\n"
		try:
			arch = detect_arch(efi)
			gdt_path = choose_gdt(arch)
			yield ev({"type": "phase", "msg": "Sample: %s  ·  arch: %s" % (orig_name, arch or "unknown")})
			yield ev({"type": "phase", "msg": "GDT: %s" % (os.path.basename(gdt_path) if gdt_path else "none")})
			yield ev({"type": "phase", "msg": "Running Behemoth analysis pipeline…"})
			rc = None
			for kind, payload in stream_headless(efi, job, gdt_path, arch):
				if kind == "line":
					yield ev({"type": "log", "line": payload})
				elif kind == "rc":
					rc = payload
			yield ev({"type": "phase", "msg": "Preparing findings…"})
			report = collect(program_name, efi)
			report["sample"]["filename"] = orig_name
			report["sample"]["arch"] = arch or "unknown"
			report["_gdt"] = {"selected": os.path.basename(gdt_path) if gdt_path else None,
							"arch": arch or "unknown"}
			report["_ghidra"] = {"returncode": rc}
			yield ev({"type": "result", "report": report})
		except Exception as e:
			yield ev({"type": "log", "line": "[backend error] " + str(e)})
			yield ev({"type": "result", "report": {"error": str(e)}})
		finally:
			cleanup_reports(program_name)
			shutil.rmtree(job, ignore_errors=True)

	return Response(stream_with_context(gen()), mimetype="application/x-ndjson",
					headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})


@app.route("/brand/logo")
def brand_logo():
	if not LOGO_PATH:
		return Response(status=404)
	return send_file(LOGO_PATH)


@app.route("/")
def index():
	return render_template_string(INDEX_HTML)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Behemoth · Firmware Vulnerability Hunting</title>
<style>
:root{
	--bg:#090d13;--panel:#111821;--panel2:#0d131b;--border:#263241;
	--fg:#e9eef5;--muted:#8592a3;--accent:#6ea8fe;
	--critical:#ff5d5d;--high:#ff984f;--medium:#e7bc55;
	--low:#67a9ff;--review:#b184f5;--info:#8b98a8;
}
*{box-sizing:border-box}
body{
	margin:0;background:
	radial-gradient(circle at 50% -20%,#172437 0,transparent 38rem),
	var(--bg);color:var(--fg);
	font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.shell{width:min(1120px,calc(100% - 40px));margin:0 auto;padding:54px 0 70px}
.hero{text-align:center;margin-bottom:34px}
.logo{width:108px;height:108px;object-fit:contain;margin-bottom:16px;filter:drop-shadow(0 10px 30px rgba(0,0,0,.35))}
.logo.missing{display:none}
h1{font-size:30px;letter-spacing:.2px;margin:0;font-weight:720}
.subtitle{color:var(--muted);margin:7px 0 0;font-size:14px}
.pipeline{color:#64758a;font-size:12px;letter-spacing:.11em;text-transform:uppercase;margin-top:12px}
#drop{
	border:1px dashed #405168;border-radius:14px;padding:34px;text-align:center;
	color:var(--muted);cursor:pointer;transition:.18s;background:rgba(17,24,33,.78);
	box-shadow:0 18px 60px rgba(0,0,0,.15)
}
#drop:hover,#drop.over{border-color:var(--accent);background:#131d29;color:var(--fg)}
#drop b{color:var(--fg);font-weight:650}
#phase{margin:14px 2px;color:var(--accent);font-size:13px;min-height:20px}
.results-head{display:flex;justify-content:space-between;align-items:flex-end;gap:18px;margin:30px 0 12px}
.results-head h2{font-size:18px;margin:0}
.results-head .count{color:var(--muted);font-size:12px}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 15px}
.chip{padding:4px 9px;border-radius:999px;font-size:11px;border:1px solid var(--border);font-weight:650}
.chip.n{opacity:.28}
.meta{
	background:var(--panel2);border:1px solid var(--border);border-radius:10px;
	color:var(--muted);font:12px/1.65 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
	margin:0 0 18px;padding:11px 13px;word-break:break-all
}
.finding{
	background:var(--panel);border:1px solid var(--border);border-left-width:4px;
	border-radius:10px;margin:9px 0;overflow:hidden
}
.finding summary{
	list-style:none;cursor:pointer;padding:14px 15px;display:flex;
	align-items:center;justify-content:space-between;gap:16px
}
.finding summary::-webkit-details-marker{display:none}
.finding summary:after{content:"＋";color:var(--muted);font-size:17px;margin-left:8px}
.finding[open] summary:after{content:"−"}
.finding-title{display:flex;align-items:center;gap:11px;min-width:0;font-weight:650}
.finding-body{border-top:1px solid var(--border);padding:13px 15px 15px;color:#c9d3df}
.finding-body p{margin:0 0 9px}
.loc{color:var(--muted);font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.sev{font-size:10px;text-transform:uppercase;letter-spacing:.09em;padding:3px 8px;border-radius:5px;white-space:nowrap}
.bcritical{border-left-color:var(--critical)}.bhigh{border-left-color:var(--high)}
.bmedium{border-left-color:var(--medium)}.blow{border-left-color:var(--low)}
.breview{border-left-color:var(--review)}.binfo{border-left-color:var(--info)}
.sevbg-critical{background:rgba(255,93,93,.12);color:var(--critical)}
.sevbg-high{background:rgba(255,152,79,.12);color:var(--high)}
.sevbg-medium{background:rgba(231,188,85,.12);color:var(--medium)}
.sevbg-low{background:rgba(103,169,255,.12);color:var(--low)}
.sevbg-review{background:rgba(177,132,245,.12);color:var(--review)}
.sevbg-info{background:rgba(139,152,168,.12);color:var(--info)}
.toolbox{margin-top:24px;border-top:1px solid var(--border);padding-top:18px}
.toolbox details{background:var(--panel2);border:1px solid var(--border);border-radius:10px;margin-top:9px}
.toolbox summary{cursor:pointer;color:var(--muted);padding:11px 13px;font-size:12px}
pre{
	margin:0;border-top:1px solid var(--border);padding:12px 13px;background:#070a0f;
	overflow:auto;font:11px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
	max-height:390px
}
#log{white-space:pre-wrap;word-break:break-word}
#log .l{color:#778495}#log .hot{color:var(--fg)}#log .gdt{color:var(--medium)}
#log .evd{color:var(--low)}#log .err{color:var(--critical)}#log .hdr{color:var(--review);font-weight:600}
.empty{color:var(--muted);padding:22px 0}
@media(max-width:650px){
	.shell{width:min(100% - 24px,1120px);padding-top:30px}
	h1{font-size:24px}.results-head{align-items:flex-start;flex-direction:column}
}
</style>
</head>
<body>
<main class="shell">
	<header class="hero">
		<img class="logo" src="/brand/logo" alt="Behemoth" onerror="this.classList.add('missing')">
		<h1>Behemoth</h1>
		<p class="subtitle">Hunting Firmware Vulnerabilities Across the Boot Chain</p>
		<div class="pipeline">Build · Evolve · Hunt · Inspect · Weaponize</div>
	</header>

	<section id="drop">
		Drop a UEFI binary here or <b>choose a file</b>
		<input id="file" type="file" accept=".efi,.bin,application/octet-stream" hidden>
	</section>

	<div id="phase"></div>

	<!-- Findings are deliberately above diagnostics. -->
	<section id="out"></section>

	<section id="diagnostics" class="toolbox" hidden>
		<details>
			<summary>Analysis console</summary>
			<pre id="log"></pre>
		</details>
		<details id="raw-wrap" hidden>
			<summary>Raw analysis report</summary>
			<pre id="raw"></pre>
		</details>
	</section>
</main>

<script>
const drop=document.getElementById('drop');
const file=document.getElementById('file');
const out=document.getElementById('out');
const phase=document.getElementById('phase');
const log=document.getElementById('log');
const raw=document.getElementById('raw');
const rawWrap=document.getElementById('raw-wrap');
const diagnostics=document.getElementById('diagnostics');
const SEV=['critical','high','medium','low','review','info'];

drop.onclick=()=>file.click();
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{
	e.preventDefault();drop.classList.remove('over');
	if(e.dataTransfer.files[0])send(e.dataTransfer.files[0]);
};
file.onchange=()=>{if(file.files[0])send(file.files[0])};

function esc(s){
	return String(s==null?'':s).replace(/[&<>"']/g,c=>({
		'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
	}[c]));
}

function cls(t){
	if(/error|exception|\[!\]|NOT FOUND|failed|timeout/i.test(t))return 'err';
	if(/====|BEHEMOTH|Behemoth -/.test(t))return 'hdr';
	if(/\[GDT\]|\.gdt|GUID DB|\[\d\/\d\]/i.test(t))return 'gdt';
	if(/\[EVIDENCE|VERDICT|FINDINGS|\[CRITICAL\]|\[HIGH\]/.test(t))return 'evd';
	if(/^\s*\[|BEHEMOTH|Behemoth|Pass \d|CONVERGED/.test(t))return 'hot';
	return 'l';
}

function addLog(t){
	const div=document.createElement('div');
	div.className=cls(t);
	div.textContent=t;
	log.appendChild(div);
	while(log.childNodes.length>1800)log.removeChild(log.firstChild);
}

async function send(f){
	out.innerHTML='';
	log.innerHTML='';
	raw.textContent='';
	rawWrap.hidden=true;
	diagnostics.hidden=false;
	phase.textContent='Analyzing '+f.name+'…';

	const fd=new FormData();
	fd.append('file',f);

	let res;
	try{
		res=await fetch('/analyze',{method:'POST',body:fd});
	}catch(err){
		phase.textContent='';
		out.innerHTML='<p class="empty">Request failed: '+esc(err)+'</p>';
		return;
	}

	const reader=res.body.getReader();
	const dec=new TextDecoder();
	let buf='';

	while(true){
		const {value,done}=await reader.read();
		if(done)break;
		buf+=dec.decode(value,{stream:true});

		let nl;
		while((nl=buf.indexOf('\n'))>=0){
			const line=buf.slice(0,nl);
			buf=buf.slice(nl+1);
			if(!line.trim())continue;

			let msg;
			try{msg=JSON.parse(line)}catch(e){continue}

			if(msg.type==='phase'){
				phase.textContent=msg.msg;
				addLog('=== '+msg.msg+' ===');
			}else if(msg.type==='log'){
				addLog(msg.line);
			}else if(msg.type==='result'){
				phase.textContent='Analysis complete.';
				render(msg.report);
			}
		}
	}
}

function render(rep){
	if(rep.error){
		out.innerHTML='<p class="empty">'+esc(rep.error)+'</p>';
		return;
	}

	const findings=rep.findings||[];
	const S=rep.summary||{};
	const m=rep.sample||{};
	const gdt=rep._gdt||{};

	let h='<div class="results-head"><h2>Findings</h2>'+
		'<div class="count">'+findings.length+' result'+(findings.length===1?'':'s')+'</div></div>';

	h+='<div class="chips">'+SEV.map(s=>
		'<span class="chip sevbg-'+s+(S[s]?'':' n')+'">'+
		esc(s)+' '+(S[s]||0)+'</span>').join('')+'</div>';

	h+='<div class="meta">'+
	esc(m.filename)+' · '+(m.size||0)+' B · '+esc(m.arch||'?')+
	(gdt.selected?' · '+esc(gdt.selected):'')+
	'<br>SHA-256 '+esc(m.sha256||'')+
	'</div>';

	for(const f of findings){
		const s=(f.severity||'info').toLowerCase();
		const context=[f.location,f.detector].filter(Boolean).join(' · ');

		h+='<details class="finding b'+esc(s)+'">'+
		'<summary>'+
			'<div class="finding-title">'+
			'<span class="sev sevbg-'+esc(s)+'">'+esc(s)+'</span>'+
			'<span>'+esc(f.name)+'</span>'+
			'</div>'+
		'</summary>'+
		'<div class="finding-body">'+
			(f.description?'<p>'+esc(f.description)+'</p>':'')+
			(context?'<div class="loc">'+esc(context)+'</div>':'')+
		'</div>'+
		'</details>';
	}

	if(!findings.length){
		h+='<div class="empty">No findings were produced by the active hunters.</div>';
	}

	out.innerHTML=h;
	raw.textContent=JSON.stringify(rep,null,2);
	rawWrap.hidden=false;
}
</script>
</body>
</html>"""


if __name__ == "__main__":
	print("Behemoth Website")
	print("Framework :", BASE)
	print("Evolve    :", EVOLVE_DIR)
	print("Hunt      :", HUNT_DIR)
	print("GDT       :", GDT_DIR)
	print("Logo      :", LOGO_PATH or "not found")
	print("Headless  :", HEADLESS or "not found")
	app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
