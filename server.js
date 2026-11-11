"use strict";
// Node 20+; no third-party dependencies. Reverse proxy must terminate HTTPS.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const RETENTION_DAYS = Math.min(365, Math.max(1, Number(process.env.RETENTION_DAYS || 30)));
const LOG_DIR = path.join(__dirname, 'data');
const PUBLIC = new Map([['/','index.html'],['/index.html','index.html'],['/style.css','style.css']]);
fs.mkdirSync(LOG_DIR, {recursive:true, mode:0o700});

function cleanIP(value) {
  if (typeof value !== 'string') return null;
  let ip = value.trim();
  if (ip.startsWith('::ffff:')) ip=ip.slice(7);
  return net.isIP(ip) ? ip : null;
}
function visitorIP(req) {
  const peer = cleanIP(req.socket.remoteAddress) || 'unknown';
  if (!TRUST_PROXY) return peer;
  // Trust forwarded values only from local reverse proxy connections.
  if (peer !== '127.0.0.1' && peer !== '::1') return peer;
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff !== 'string') return peer;
  // Reverse proxy MUST replace (not append to) the header with the actual client IP.
  return cleanIP(xff) || peer;
}
function safe(value, max=300) {
  return typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g,' ').slice(0,max) : '';
}
function deviceInfo(ua, headers) {
  const s = ua.toLowerCase();
  const os = /android/.test(s) ? 'Android' : /iphone|ipad|ipod/.test(s) ? 'iOS/iPadOS' : /windows/.test(s) ? 'Windows' : /mac os x|macintosh/.test(s) ? 'macOS' : /linux/.test(s) ? 'Linux' : 'Unknown';
  const browser = /edg\//.test(s) ? 'Edge' : /firefox\//.test(s) ? 'Firefox' : /chrome\//.test(s) ? 'Chrome/Chromium' : /safari\//.test(s) ? 'Safari' : 'Unknown';
  const hint = headers['sec-ch-ua-mobile'];
  const category = /ipad|tablet/.test(s) ? 'tablet' : hint === '?1' || /mobile|iphone|android/.test(s) ? 'mobile' : 'desktop/unknown';
  return {os, browser, category}; // Heuristics, not proof of a device identity.
}
function json(res, status, value) {
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});
  res.end(JSON.stringify(value));
}
function authenticated(req) {
  if (ADMIN_TOKEN.length < 32) return false;
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const a = Buffer.from(token); const b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a,b);
}
function dateFile(date) { return path.join(LOG_DIR, `visitors-${date}.jsonl`); }
function record(req, pathname, eventType='page_view') {
  const now = new Date();
  const ua = safe(req.headers['user-agent'], 512);
  const event = {
    id:crypto.randomUUID(), timestamp:now.toISOString(), event:eventType,
    ip:visitorIP(req), method:req.method, path:pathname,
    userAgent:ua, device:deviceInfo(ua, req.headers),
    referrerOrigin:(() => { try { const r=req.headers.referer; return r ? new URL(r).origin.slice(0,200) : null; } catch {return null;} })()
  };
  fs.appendFile(dateFile(now.toISOString().slice(0,10)), JSON.stringify(event)+'\n', {mode:0o600}, err => {
    if(err) console.error('Visitor logging failed:',err.message);
  });
}
function purgeOldLogs() {
  const cutoff = Date.now()-RETENTION_DAYS*86400000;
  fs.readdir(LOG_DIR, (err,names)=>{
    if(err) return;
    for(const name of names){
      const m=/^visitors-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(name);
      if(m && Date.parse(m[1]+'T00:00:00Z') < cutoff) fs.unlink(path.join(LOG_DIR,name),()=>{});
    }
  });
}
purgeOldLogs();
setInterval(purgeOldLogs, 86400000).unref();

function serve(res, filename, mime) {
  fs.readFile(path.join(__dirname,filename),(err,bytes)=>{
    if(err) return json(res,404,{error:'Not found'});
    res.writeHead(200,{'Content-Type':mime,'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Cache-Control':'no-store',
      'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"});
    res.end(bytes);
  });
}
const server = http.createServer((req,res)=>{
  let pathname;
  try {pathname=new URL(req.url,'http://localhost').pathname;} catch {return json(res,400,{error:'Invalid URL'});}
  if(req.method!=='GET') return json(res,405,{error:'Method not allowed'});
  if(pathname==='/api/my-ip') return json(res,200,{ip:visitorIP(req)});
  if(pathname==='/api/admin/visitors') {
    if(!authenticated(req)) return json(res,401,{error:'Unauthorized'});
    const date = new URL(req.url,'http://localhost').searchParams.get('date') || new Date().toISOString().slice(0,10);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return json(res,400,{error:'Invalid date'});
    // Limit output; for higher traffic use a proper database with pagination.
    fs.readFile(dateFile(date),'utf8',(err,content)=>{
      if(err && err.code==='ENOENT') return json(res,200,{date,events:[]});
      if(err) return json(res,500,{error:'Could not read log'});
      const lines=content.trim().split('\n').filter(Boolean).slice(-200);
      return json(res,200,{date,events:lines.map(line=>{try{return JSON.parse(line)}catch{return null}}).filter(Boolean)});
    });
    return;
  }
  if(!PUBLIC.has(pathname)) return json(res,404,{error:'Not found'});
  if(pathname==='/' || pathname==='/index.html') record(req,pathname);
  serve(res,PUBLIC.get(pathname),pathname==='/style.css'?'text/css; charset=utf-8':'text/html; charset=utf-8');
});
server.requestTimeout=15000;
server.headersTimeout=10000;
server.listen(PORT,HOST,()=>console.log(`Website: http://${HOST}:${PORT} | logs: ${LOG_DIR} | retention: ${RETENTION_DAYS} days`));
