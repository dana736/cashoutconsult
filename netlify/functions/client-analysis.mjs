import { getStore } from '@netlify/blobs';
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
const COOKIE='__Host-cashout_team';
const eq=(a,b)=>timingSafeEqual(createHash('sha256').update(String(a)).digest(),createHash('sha256').update(String(b)).digest());
const reply=(status,body,headers={})=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store','X-Content-Type-Options':'nosniff',...headers}});
export default async function(req){
 try{
 const secret=process.env.CASHOUT_TEAM_PASSWORD;
 if(!secret||secret.length<16)return reply(503,{error:'Team password not configured. Contact administrator.'});
 const url=new URL(req.url), action=url.searchParams.get('action'), lead=url.searchParams.get('lead');
 const sign=t=>createHmac('sha256',secret).update('cashout-session:'+t).digest('hex');
 const cookie=(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||'';
 const [expiry,sig]=cookie.split('.');
 const valid=!!sig&&/^\d+$/.test(expiry)&&Number(expiry)>Date.now()&&eq(sig,sign(expiry));
 if(req.method==='POST' && (req.headers.get('origin')!==url.origin||!req.headers.get('content-type')?.startsWith('application/json')))return reply(403,{error:'Invalid request origin or format.'});
 if(action==='login'&&req.method==='POST'){
  const raw=await req.text(); if(raw.length>4096)return reply(400,{error:'Invalid password.'});
  const {password}=JSON.parse(raw); if(typeof password!=='string'||!eq(password,secret))return reply(401,{error:'Incorrect team password.'});
  const t=String(Date.now()+12*60*60*1000);return reply(200,{ok:true},{'Set-Cookie':`${COOKIE}=${t}.${sign(t)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200`});
 }
 if(action==='logout'&&req.method==='POST')return reply(200,{ok:true},{'Set-Cookie':`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`});
 if(!valid)return reply(401,{error:'Team login required.'});
 if(action==='session'&&req.method==='GET')return reply(200,{ok:true});
 if(!/^lead_[A-Za-z0-9_-]{1,150}$/.test(lead||''))return reply(400,{error:'Invalid Close lead ID.'});
 const store=getStore({name:'cashout-client-analysis-v1',consistency:'strong'});
 if(req.method==='GET'){
  const row=await store.getWithMetadata(lead,{type:'json'});return reply(200,{record:row?.data??null,etag:row?.etag??null});
 }
 if(req.method==='POST'){
  const raw=await req.text();if(Buffer.byteLength(raw)>1000000)return reply(413,{error:'Analysis exceeds the 1 MB limit.'});
  const {data,etag}=JSON.parse(raw);
  if(!data||data.version!==1||!data.inputs||typeof data.inputs!=='object'||Array.isArray(data.inputs)||!Object.values(data.inputs).every(v=>typeof v==='string')||!Array.isArray(data.planDone)||!data.planDone.every(v=>typeof v==='string')||!['Likely','Conservative','Upside'].includes(data.active)||typeof data.quiz!=='string'||!(etag===null||typeof etag==='string'))return reply(400,{error:'Invalid analysis data.'});
  const updatedAt=new Date().toISOString();const result=await store.setJSON(lead,{data,updatedAt},etag===null?{onlyIfNew:true}:{onlyIfMatch:etag});
  if(!result.modified)return reply(409,{error:'Another team member saved this lead. Copy Full Analysis as a backup, then reload to see their changes.'});
  return reply(200,{etag:result.etag,updatedAt});
 }
 return reply(405,{error:'Method not allowed.'});
 }catch(e){return reply(500,{error:'Unable to complete request. Retry or contact administrator.'});}
}
