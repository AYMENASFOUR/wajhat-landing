'use strict';
const crypto=require('node:crypto');
const COOKIE='__Host-wajhat_admin', TTL=900, MAX=4096;
const attempts=new Map();
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hash=s=>crypto.createHash('sha256').update(s).digest();
const equal=(a,b)=>crypto.timingSafeEqual(hash(String(a)),hash(String(b)));
function base32(s){
 if(!/^[A-Z2-7]{32,128}$/.test(s))return null;
 let bits=0,n=0,bytes=[];
 for(const ch of s){n=(n<<5)|'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch);bits+=5;if(bits>=8){bits-=8;bytes.push((n>>bits)&255);n&=(1<<bits)-1}}
 if(n!==0)return null;return Buffer.from(bytes);
}
function config(res){
 const fail=reason=>{console.warn('WAJHAT_ADMIN_CONFIG_CHECK: '+reason);if(res && process.env.VERCEL_ENV!=='production')res.setHeader('X-Wajhat-Setup-Status',reason);return null};
 const raw=process.env.WAJHAT_ADMIN_AUTH;
 if(typeof raw!=='string'||!raw.trim())return fail('missing');
 try{
 const v=JSON.parse(raw.trim().replace(/^\uFEFF/,''));
 if(!v||v.v!==1)return fail('version_or_structure');
 if(typeof v.salt!=='string')return fail('salt_not_string');
 // Accept canonical hexadecimal salts of 16–32 bytes and explicit hex prefix.
 // Never truncate the salt or guess its bytes.
 let saltHex=v.salt.trim();
 if(/^(?:"[a-fA-F0-9]+"|'[a-fA-F0-9]+')$/.test(saltHex))saltHex=saltHex.slice(1,-1);
 saltHex=saltHex.replace(/^0x/i,'');
 if(!/^(?:[a-fA-F0-9]{2}){16,32}$/.test(saltHex)){
 const count=(saltHex.match(/[a-fA-F0-9]/g)||[]).length;
 return fail('salt_invalid_hex_count_'+Math.min(count,999)+'_length_'+Math.min(saltHex.length,999));
 }
 if(typeof v.verifier!=='string'||!(/^[a-fA-F0-9]{64}$/.test(v.verifier)))return fail('verifier_format');
 if(typeof v.sessionKey!=='string'||!(/^[a-fA-F0-9]{64}$/.test(v.sessionKey)))return fail('session_key_format');
 if(typeof v.totp!=='string'||!(/^[A-Z2-7]{32}$/.test(v.totp)))return fail('totp_format');
 const secret=base32(v.totp);if(!secret)return fail('totp_decode');
 const replacement=process.env.WAJHAT_ADMIN_PASSWORD;
 if(replacement!==undefined){
  let p;try{p=JSON.parse(replacement)}catch{return fail('password_override_invalid')}
  if(!p||p.v!==1||typeof p.salt!=='string'||!/^[a-f0-9]{32}$/.test(p.salt)||typeof p.verifier!=='string'||!/^[a-f0-9]{64}$/.test(p.verifier))return fail('password_override_invalid');
  // Revoke sessions issued before password rotation without changing the enrolled TOTP.
  const key=crypto.createHmac('sha256',Buffer.from(v.sessionKey,'hex')).update('password-rotation-v1:').update(p.salt).update(p.verifier).digest();
  return {salt:Buffer.from(p.salt,'hex'),verifier:Buffer.from(p.verifier,'hex'),secret,key};
 }
 return {salt:Buffer.from(saltHex,'hex'),verifier:Buffer.from(v.verifier,'hex'),secret,key:Buffer.from(v.sessionKey,'hex')};
 }catch{return fail('invalid_json')}
}
function validPassword(cfg,password){
 const derived=crypto.pbkdf2Sync(password,cfg.salt,600000,32,'sha256');
 return crypto.timingSafeEqual(derived,cfg.verifier);
}
function otp(secret,step){
 const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(step));
 const mac=crypto.createHmac('sha1',secret).update(buf).digest(),i=mac[mac.length-1]&15;
 return String((mac.readUInt32BE(i)&0x7fffffff)%1000000).padStart(6,'0');
}
function validOtp(secret,code,now=Date.now()){
 if(typeof code!=='string'||!/^\d{6}$/.test(code))return false;
 const step=Math.floor(now/30000);let match=false;
 for(const i of [-1,0,1])match=equal(code,otp(secret,step+i))||match;
 return match;
}
function sig(key,payload){return crypto.createHmac('sha256',key).update(payload).digest('base64url')}
function issue(key,now=Math.floor(Date.now()/1000)){
 const body=Buffer.from(JSON.stringify({v:1,iat:now,exp:now+TTL,n:crypto.randomBytes(16).toString('hex')})).toString('base64url');
 return body+'.'+sig(key,body);
}
function verify(key,token,now=Math.floor(Date.now()/1000)){
 try{if(typeof token!=='string'||token.length>512)return false;const parts=token.split('.');if(parts.length!==2||!equal(sig(key,parts[0]),parts[1]))return false;
 const p=JSON.parse(Buffer.from(parts[0],'base64url').toString('utf8'));
 return p.v===1&&Number.isInteger(p.iat)&&Number.isInteger(p.exp)&&p.iat<=now&&p.exp>now&&p.exp-p.iat===TTL&&/^[a-f0-9]{32}$/.test(p.n);
 }catch{return false}
}
function cookie(req){return String(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE+'='))?.slice(COOKIE.length+1)||''}
function setCookie(res,value,age){res.setHeader('Set-Cookie',COOKIE+'='+value+'; Path=/; Max-Age='+age+'; HttpOnly; Secure; SameSite=Strict')}
function sameOrigin(req){
 const host=String(req.headers.host||'').toLowerCase();
 if(!/^[a-z0-9.-]+$/.test(host))return false;
 const allowed=['www.wajhat.co','wajhat.co',process.env.VERCEL_URL,process.env.VERCEL_BRANCH_URL,process.env.VERCEL_PROJECT_PRODUCTION_URL].filter(Boolean).map(x=>x.toLowerCase());
 return allowed.includes(host)&&req.headers.origin==='https://'+host;
}
function throttle(req,now=Date.now()){
 for(const [k,v] of attempts)if(v.until<=now)attempts.delete(k);
 const ip=String(req.headers['x-vercel-forwarded-for']||req.headers['x-forwarded-for']||'unknown').split(',')[0].trim().slice(0,64);
 if(attempts.size>=1000&&!attempts.has(ip))return false;
 const a=attempts.get(ip)||{count:0,until:now+300000},g=attempts.get('*global*')||{count:0,until:now+60000};
 if(a.count>=5||g.count>=30)return false;a.count++;g.count++;attempts.set(ip,a);attempts.set('*global*',g);return true;
}
function safeLink(url){
 try{const u=new URL(url);if(u.protocol!=='https:'||u.username||u.password||!['github.com','vercel.com','supabase.com','www.wajhat.co','wajhat.co','cost.wajhat.co','kitchen.wajhat.co','cladding.wajhat.co'].includes(u.hostname))return '';return u.href}catch{return ''}
}
const css='*{box-sizing:border-box}body{margin:0;background:#f3f6f9;color:#182b3e;font:15px/1.65 Tahoma,Arial,sans-serif}main{width:min(1250px,100%);margin:auto;padding:20px}header{background:#142e45;color:#fff;padding:15px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}header b{font-size:19px}header small{color:#edc77e}h1,h2,h3,p{margin:0}h1{font-size:25px}h2{font-size:20px;margin-bottom:12px}p{color:#4b6073}button,a.btn{display:inline-block;border:1px solid #c9d6e1;background:#183c56;color:#fff;border-radius:8px;min-height:42px;padding:8px 14px;font:inherit;font-weight:bold;cursor:pointer;text-decoration:none}a{color:#195f91}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #1765ab;outline-offset:3px}.panel{border:1px solid #d5dfe7;background:#fff;border-radius:13px;padding:18px;margin:14px 0}.login{max-width:460px;margin:9vh auto}.login label{display:block;font-weight:bold;margin-top:15px}.login input{width:100%;border:1px solid #bfcfda;border-radius:7px;padding:12px;font:inherit;direction:ltr;text-align:left}.login button{width:100%;margin-top:18px}.warn{padding:11px;background:#fff5df;color:#744b12;border-radius:8px;margin:12px 0}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{border:1px solid #d5dfe7;background:#fff;border-radius:11px;padding:16px}.metric b{font-size:29px;display:block}.badge{display:inline-block;background:#e8f0f7;border-radius:5px;padding:4px 8px;font-size:12px}.products{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.project{border:1px solid #d5dfe7;padding:13px;border-radius:9px}.project h3{font-size:16px}.links{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}.links a{padding:4px 8px;border:1px solid #d5dfe7;border-radius:6px;text-decoration:none}.list{display:grid;gap:8px}.item{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr) auto;align-items:center;gap:8px;border-bottom:1px solid #e5ebf0;padding:8px 0;overflow-wrap:anywhere}.item:last-child{border:0}.name{direction:ltr;text-align:right;font-weight:bold}.meta{font-size:12px;color:#4b6073}.footer{font-size:12px;color:#4b6073;margin-top:12px}.tabs{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.tabs a{border:1px solid #d5dfe7;padding:6px 10px;border-radius:6px;background:white;text-decoration:none}section{scroll-margin-top:15px}@media(max-width:600px){main{padding:12px}.products{grid-template-columns:1fr}.metric{padding:10px}.metric b{font-size:23px}.item{grid-template-columns:1fr auto}.item .meta{grid-row:2;grid-column:1/-1}.panel{padding:13px}h1{font-size:21px}}';
function shell(content,logged=false){
 return '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>WAJHAT | الإدارة الداخلية</title><style>'+css+'</style></head><body><header><div><b>واجهات | WAJHAT</b><br><small>الإدارة الداخلية</small></div>'+(logged?'<form method="post" action="/admin"><input type="hidden" name="action" value="logout"><button type="submit">تسجيل الخروج</button></form>':'')+'</header><main>'+content+'</main></body></html>';
}
function login(message){return shell('<section class="panel login"><h1>دخول المالك</h1><p>لوحة خاصة — التحقق الثنائي مطلوب.</p>'+(message?'<div class="warn" role="alert">'+esc(message)+'</div>':'')+'<form method="post" action="/admin"><input type="hidden" name="action" value="login"><label for="pw">كلمة المرور</label><input id="pw" type="password" name="password" autocomplete="current-password" required maxlength="256"><label for="otp">رمز تطبيق المصادقة</label><input id="otp" name="otp" type="text" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" required><button type="submit">دخول آمن</button></form></section>')}
function readInventory(){try{const d=JSON.parse(process.env.WAJHAT_ADMIN_INVENTORY||'null');if(!d||!['github','vercel','supabase','products'].every(k=>Array.isArray(d[k])))return null;return d}catch{return null}}
function dashboard(d){
 if(!d)return shell('<section class="panel"><h1>لوحة الإدارة</h1><div class="warn">سجل المشاريع غير مهيأ. لا توجد بيانات معروضة.</div></section>',true);
 const groups=[['github','GitHub','المستودعات'],['vercel','Vercel','الاستضافة'],['supabase','Supabase','قواعد البيانات']];
 const metrics=groups.map(([k,n,l])=>'<div class="metric"><bdi>'+esc(n)+'</bdi><b>'+d[k].length+'</b><p>'+esc(l)+'</p></div>').join('');
 const link=(label,url)=>{const u=safeLink(url);return u?'<a href="'+esc(u)+'" target="_blank" rel="noopener noreferrer">'+esc(label)+'</a>':''};
 const products=d.products.map(p=>'<article class="project"><h3>'+esc(p.name)+'</h3><span class="badge">'+esc(p.status)+'</span><p>'+esc(p.next)+'</p><div class="links">'+(Array.isArray(p.links)?p.links.map(l=>link(l.label,l.url)).join(''):'')+'</div></article>').join('');
 const tables=groups.map(([k,n,l])=>'<section class="panel" id="'+k+'"><h2>'+esc(n)+' — '+esc(l)+'</h2><div class="list">'+d[k].map(p=>'<div class="item"><span class="name" dir="ltr">'+esc(p.name)+'</span><span class="meta">'+esc(p.account)+' · '+esc(p.status)+'</span>'+link('فتح لوحة المشروع',p.url)+'</div>').join('')+'</div></section>').join('');
 return shell('<h1>مركز التحكم بالمشاريع</h1><p>سجل مركزي للقراءة فقط — آخر حصر: <bdi>'+esc(d.asOf)+'</bdi>. لا يتضمن كلمات مرور أو مفاتيح API.</p><div class="metrics" style="margin-top:15px">'+metrics+'</div><section class="panel"><h2>المشاريع ذات الأولوية</h2><div class="products">'+products+'</div><p class="footer">الحالات التنفيذية حسب آخر قرار إداري؛ لا تعني اختبارًا لحظيًا. الفواتير ونسب الإنجاز غير المقاسة لم تُدرج.</p></section><nav class="tabs"><a href="#github">GitHub</a><a href="#vercel">Vercel</a><a href="#supabase">Supabase</a></nav>'+tables+'<p class="footer">هذه لقطة حصر مؤرخة وليست مزامنة لحظية. الحساب الرئيسي والثانوي لا يزالان منفصلين. لا توجد أوامر نقل أو حذف.</p>',true);
}
function headers(res){res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Cache-Control','private, no-store, max-age=0');res.setHeader('Pragma','no-cache');res.setHeader('Vercel-CDN-Cache-Control','no-store');res.setHeader('X-Robots-Tag','noindex, nofollow, noarchive');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")}
function send(res,status,body){res.statusCode=status;res.end(body)}
function parse(req){
 if(!/^application\/x-www-form-urlencoded(?:;|$)/i.test(String(req.headers['content-type']||'')))return null;
 if(Number(req.headers['content-length']||0)>MAX)return null;
 if(typeof req.body==='string'){if(req.body.length>MAX)return null;const q=new URLSearchParams(req.body);return Object.fromEntries(q)}
 if(req.body&&typeof req.body==='object'&&!Buffer.isBuffer(req.body))return req.body;return null;
}
function handler(req,res){
 headers(res);const cfg=config(res);
 if(!cfg)return send(res,503,shell('<section class="panel login"><h1>لوحة الإدارة غير مفعلة</h1><p>يجب إكمال إعداد بيانات المصادقة على الخادم أولًا. لا تُعرض أي بيانات قبل التفعيل.</p></section>'));
 if(req.method==='GET'||req.method==='HEAD')return send(res,200,req.method==='HEAD'?'':verify(cfg.key,cookie(req))?dashboard(readInventory()):login());
 if(req.method!=='POST'){res.setHeader('Allow','GET, HEAD, POST');return send(res,405,shell('<p>الطلب غير مسموح.</p>'))}
 if(!sameOrigin(req))return send(res,403,shell('<p>الطلب غير مسموح.</p>'));
 const data=parse(req);if(!data)return send(res,400,login('طلب غير صالح.'));
 if(data.action==='logout'){setCookie(res,'',0);res.statusCode=303;res.setHeader('Location','/admin');return res.end()}
 if(data.action!=='login'||typeof data.password!=='string'||data.password.length>256||typeof data.otp!=='string')return send(res,400,login('طلب غير صالح.'));
 if(!throttle(req)){res.setHeader('Retry-After','300');return send(res,429,login('محاولات كثيرة. حاول لاحقًا.'))}
 const okPass=validPassword(cfg,data.password),okOtp=validOtp(cfg.secret,data.otp);
 if(!okPass||!okOtp)return send(res,401,login('تعذر تسجيل الدخول. تحقق من بيانات المصادقة.'));
 setCookie(res,issue(cfg.key),TTL);res.statusCode=303;res.setHeader('Location','/admin');return res.end();
}
module.exports=handler;
