const dns = require('node:dns').promises;
const net = require('node:net');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const COMMON_PORTS = [20,21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1521,2049,2375,3000,3306,3389,5000,5432,5900,6379,8000,8080,8443,8888,9200,27017];
const MAX_PORTS = 64;

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function validIPv4(value) {
  const p = String(value || '').trim().split('.');
  return p.length === 4 && p.every(x => /^\d+$/.test(x) && Number(x) >= 0 && Number(x) <= 255);
}

function portNumber(value) {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

function tcpCheck(host, port, timeout = 1800) {
  return new Promise(resolve => {
    const started = Date.now();
    const socket = new net.Socket();
    let done = false;
    const finish = (open, error = '') => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ port, open, latency_ms: Date.now() - started, error: error || undefined });
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false, 'timeout'));
    socket.once('error', err => finish(false, err.code || 'connection_error'));
    socket.connect(port, host);
  });
}

async function limitedPool(items, worker, concurrency = 8) {
  const out = new Array(items.length);
  let next = 0;
  async function run() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await worker(items[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, run));
  return out;
}

function httpProbe(target, timeout = 5000) {
  return new Promise(resolve => {
    const started = Date.now();
    let url;
    try { url = new URL(target); } catch { return resolve({ ok: false, error: 'URL tidak valid' }); }
    if (!['http:', 'https:'].includes(url.protocol)) return resolve({ ok: false, error: 'Hanya HTTP/HTTPS yang didukung' });
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, { method: 'HEAD', timeout, headers: { 'User-Agent': 'NetVanta/1.0' } }, r => {
      r.resume();
      resolve({ ok: true, status: r.statusCode, status_text: r.statusMessage, latency_ms: Date.now() - started, server: r.headers.server || null, content_type: r.headers['content-type'] || null });
    });
    req.on('timeout', () => { req.destroy(new Error('timeout')); });
    req.on('error', e => resolve({ ok: false, latency_ms: Date.now() - started, error: e.code || e.message }));
    req.end();
  });
}

function parseHostFromUrl(input) {
  let value = String(input || '').trim();
  if (!/^https?:\/\//i.test(value)) value = 'https://' + value;
  const u = new URL(value);
  return { url: u.toString(), hostname: u.hostname };
}

async function resolveHost(hostname) {
  const records = await dns.lookup(hostname, { all: true });
  return [...new Set(records.map(r => r.address))];
}

async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method harus POST' });
  let body = req.body;
  if (typeof body === 'string') { try { body = JSON.parse(body); } catch {} }
  body = body || {};
  const type = body.type;

  try {
    if (type === 'resolve') {
      const { hostname, url } = parseHostFromUrl(body.target);
      const addresses = await resolveHost(hostname);
      return json(res, 200, { type, target: url, hostname, addresses });
    }

    if (type === 'server-ip') {
      const { hostname, url } = parseHostFromUrl(body.target);
      const addresses = await resolveHost(hostname);
      const probe = await httpProbe(url);
      return json(res, 200, { type, target: url, hostname, addresses, probe });
    }

    if (type === 'port-scan' || type === 'wifi-scan') {
      const host = String(body.target || '').trim();
      if (!validIPv4(host)) return json(res, 400, { error: 'Fitur ini membutuhkan IPv4 yang valid.' });
      let ports = Array.isArray(body.ports) ? body.ports.map(portNumber).filter(Boolean) : COMMON_PORTS;
      ports = [...new Set(ports)].slice(0, MAX_PORTS);
      const results = await limitedPool(ports, p => tcpCheck(host, p), 8);
      return json(res, 200, { type, target: host, checked_ports: ports.length, open_ports: results.filter(x => x.open), results });
    }

    if (type === 'traffic') {
      const raw = String(body.target || '').trim();
      const match = raw.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
      if (!match || !validIPv4(match[1]) || !portNumber(match[2])) return json(res, 400, { error: 'Masukkan target dengan format IP:PORT, contoh 123.77.8.23:440.' });
      const result = await tcpCheck(match[1], Number(match[2]), 2500);
      return json(res, 200, { type, target: raw, sample: result, note: 'Ini adalah probe TCP aktif, bukan packet capture/promiscuous sniffing.' });
    }

    return json(res, 400, { error: 'Mode scan tidak dikenal.' });
  } catch (e) {
    return json(res, 500, { error: e.code === 'ENOTFOUND' ? 'Hostname tidak ditemukan.' : (e.message || 'Scan gagal.') });
  }
}

module.exports = handler;
