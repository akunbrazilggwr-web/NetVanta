const $ = id => document.getElementById(id);
let selectedMode = null;
let running = false;
let aborter = null;
let trafficTimer = null;

const modes = {
  resolve: { label: 'Cek IP website', kind: 'url', hint: 'URL, contoh https://example.com' },
  'server-ip': { label: 'Scan Server IP', kind: 'url', hint: 'URL server, contoh https://example.com' },
  'port-scan': { label: 'Cek Open Port', kind: 'ip', hint: 'IPv4, contoh 8.8.8.8' },
  'wifi-scan': { label: 'Scan WiFi', kind: 'ip', hint: 'IP gateway/host IPv4' },
  traffic: { label: 'Cek Network Traffic', kind: 'ipport', hint: 'IP:PORT, contoh 123.77.8.23:440' },
  special: { label: 'Special IP Scan', kind: 'url' }
};

document.querySelectorAll('.mode').forEach(btn => btn.addEventListener('click', () => selectMode(btn.dataset.mode)));
$('startBtn').addEventListener('click', startScan);
$('stopBtn').addEventListener('click', stopScan);
$('modalClose').addEventListener('click', () => $('modal').classList.add('hidden'));

document.addEventListener('DOMContentLoaded', () => {
  const ua = navigator.userAgent;
  $('osName').textContent = detectOS(ua);
  $('deviceName').textContent = detectDevice(ua);
});

function detectOS(ua){
  if(/Android/i.test(ua)) return 'Android';
  if(/iPhone|iPad|iPod/i.test(ua)) return 'iOS';
  if(/Windows/i.test(ua)) return 'Windows';
  if(/Mac OS X/i.test(ua)) return 'macOS';
  if(/Linux/i.test(ua)) return 'Linux';
  return 'Browser';
}
function detectDevice(ua){
  const m=ua.match(/Android[^;)]*;\s*(?:[a-z]{2}-[A-Z]{2};\s*)?([^;)]+?)(?:\sBuild\/[^;)]+)?[;)]/i);
  if(/iPhone/i.test(ua)) return 'iPhone';
  if(/iPad/i.test(ua)) return 'iPad';
  return m ? m[1].trim() : (innerWidth < 700 ? 'Perangkat mobile' : 'Desktop/PC');
}
function selectMode(mode){
  selectedMode=mode;
  document.querySelectorAll('.mode').forEach(b=>b.classList.toggle('selected',b.dataset.mode===mode));
  if(mode==='special') return showModal('Special IP Scan','Comming soon, masih tahap awal.');
  $('terminalTitle').textContent=`Terminal — ${modes[mode].label}`;
  log(`Mode dipilih: ${modes[mode].label}`);
  log(`Input yang didukung: ${modes[mode].hint}`);
}
function showModal(title,text){$('modalTitle').textContent=title;$('modalText').textContent=text;$('modal').classList.remove('hidden')}
function stopScan(){
  running=false;
  if(aborter) aborter.abort();
  if(trafficTimer) clearInterval(trafficTimer);
  $('statusDot').classList.remove('running');
  log('Scan dihentikan oleh pengguna.');
}
function validIPv4(v){const p=v.trim().split('.');return p.length===4&&p.every(x=>/^\d+$/.test(x)&&+x>=0&&+x<=255)}
function validateTarget(mode,target){
  if(!target) return 'Target belum diisi.';
  const k=modes[mode].kind;
  if(k==='ip' && !validIPv4(target)) return 'Maaf, fitur ini hanya bisa berjalan dengan IP IPv4 yang valid.';
  if(k==='ipport' && !/^\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}$/.test(target)) return 'Maaf, fitur ini membutuhkan format IP:PORT.';
  if(k==='url') { try { new URL(/^https?:\/\//i.test(target)?target:'https://'+target); } catch { return 'Maaf, URL tidak valid.' } }
  return null;
}
async function startScan(){
  if(running) return;
  if(!selectedMode) return showModal('Pilih fitur','Silakan pilih salah satu fitur terlebih dahulu.');
  if(selectedMode==='special') return showModal('Special IP Scan','Comming soon, masih tahap awal.');
  const target=$('target').value.trim();
  const error=validateTarget(selectedMode,target);
  if(error) return showModal('Tidak dapat berjalan',error);
  running=true; aborter=new AbortController(); $('statusDot').classList.add('running');
  log('> start'); log(`> target: ${target}`); log(`> mode: ${modes[selectedMode].label}`); log('> menjalankan pemeriksaan...');
  $('result').textContent='Memproses...';
  try{
    if(selectedMode==='traffic') await trafficLoop(target);
    else await requestScan(selectedMode,target);
  }catch(e){ if(e.name!=='AbortError'){ log(`ERROR: ${e.message}`); $('result').textContent='Scan gagal: '+e.message; }}
  if(selectedMode!=='traffic') {running=false;$('statusDot').classList.remove('running');}
}
async function requestScan(type,target){
  const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,target}),signal:aborter.signal});
  const data=await r.json();
  if(!r.ok) throw new Error(data.error||'Server scan gagal');
  renderResult(type,data); log(JSON.stringify(data,null,2));
}
async function trafficLoop(target){
  $('result').textContent='Live TCP probe berjalan. Ini bukan packet capture Wireshark.';
  const sample=async()=>{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'traffic',target}),signal:aborter.signal});
    const data=await r.json(); if(!r.ok) throw new Error(data.error||'Traffic probe gagal');
    renderResult('traffic',data); log(`[${new Date().toLocaleTimeString()}] ${JSON.stringify(data.sample)}`);
  };
  await sample(); trafficTimer=setInterval(()=>sample().catch(e=>log('ERROR: '+e.message)),2000);
}
function renderResult(type,d){
  if(type==='resolve') $('result').textContent=`Hostname: ${d.hostname}\nIP: ${d.addresses.join(', ')}`;
  if(type==='server-ip') $('result').textContent=`Hostname: ${d.hostname}\nIP server: ${d.addresses.join(', ')}\nHTTP probe: ${d.probe?.status||d.probe?.error||'n/a'}\nLatency: ${d.probe?.latency_ms??'n/a'} ms`;
  if(type==='port-scan'||type==='wifi-scan') $('result').textContent=`Target: ${d.target}\nPort diperiksa: ${d.checked_ports}\nPort terbuka: ${d.open_ports.map(x=>x.port).join(', ')||'Tidak terdeteksi dari daftar port umum.'}\n\nCatatan: scan WiFi di browser/Vercel tidak dapat mengakses radio WiFi atau melakukan brute-force password.`;
  if(type==='traffic') $('result').textContent=`Target: ${d.target}\nStatus TCP: ${d.sample.open?'OPEN':'CLOSED/FILTERED'}\nLatency: ${d.sample.latency_ms} ms\nCatatan: ${d.note}`;
}
function log(line){const el=$('terminalOutput');el.textContent += `\n${line}`;el.scrollTop=el.scrollHeight}
