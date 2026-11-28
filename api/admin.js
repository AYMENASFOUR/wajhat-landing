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
 const fail=reason=>{console.warn('WAJHAT_ADMIN_CONFIG_CHECK: '+reason);return null};
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
 return fail('salt_format');
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
const css='*{box-sizing:border-box}body{margin:0;background:#f3f6f9;color:#182b3e;font:15px/1.65 Tahoma,Arial,sans-serif}main{width:min(1250px,100%);margin:auto;padding:20px}header{background:#142e45;color:#fff;padding:15px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}header b{font-size:19px}header small{color:#edc77e}.admin-nav{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.admin-nav .home-link{background:transparent;border-color:#93a8ba}.admin-nav form{margin:0}h1,h2,h3,p{margin:0}h1{font-size:25px}h2{font-size:20px;margin-bottom:12px}p{color:#4b6073}button,a.btn{display:inline-block;border:1px solid #c9d6e1;background:#183c56;color:#fff;border-radius:8px;min-height:42px;padding:8px 14px;font:inherit;font-weight:bold;cursor:pointer;text-decoration:none}a{color:#195f91}button:focus-visible,a:focus-visible,input:focus-visible{outline:3px solid #1765ab;outline-offset:3px}.panel{border:1px solid #d5dfe7;background:#fff;border-radius:13px;padding:18px;margin:14px 0}.login{max-width:460px;margin:9vh auto}.login label{display:block;font-weight:bold;margin-top:15px}.login input{width:100%;border:1px solid #bfcfda;border-radius:7px;padding:12px;font:inherit;direction:ltr;text-align:left}.login button{width:100%;margin-top:18px}.pw-wrap{display:flex;align-items:stretch;gap:8px}.pw-wrap input{min-width:0;flex:1}.pw-wrap button{width:auto;min-width:76px;margin:0;background:#eaf0f5;color:#183c56}.pw-wrap button[hidden]{display:none}.login-progress{margin-top:12px;color:#183c56}.login button[aria-busy="true"]{opacity:.75;cursor:progress}.warn{padding:11px;background:#fff5df;color:#744b12;border-radius:8px;margin:12px 0}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.metric{border:1px solid #d5dfe7;background:#fff;border-radius:11px;padding:16px}.metric b{font-size:29px;display:block}.badge{display:inline-block;background:#e8f0f7;border-radius:5px;padding:4px 8px;font-size:12px}.products{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.project{border:1px solid #d5dfe7;padding:13px;border-radius:9px}.project h3{font-size:16px}.links{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}.links a{padding:4px 8px;border:1px solid #d5dfe7;border-radius:6px;text-decoration:none}.list{display:grid;gap:8px}.item{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(0,1fr) auto;align-items:center;gap:8px;border-bottom:1px solid #e5ebf0;padding:8px 0;overflow-wrap:anywhere}.item:last-child{border:0}.name{direction:ltr;text-align:right;font-weight:bold}.meta{font-size:12px;color:#4b6073}.footer{font-size:12px;color:#4b6073;margin-top:12px}.tabs{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.tabs a{border:1px solid #d5dfe7;padding:6px 10px;border-radius:6px;background:white;text-decoration:none}section{scroll-margin-top:15px}@media(max-width:600px){main{padding:12px}.products{grid-template-columns:1fr}.metric{padding:10px}.metric b{font-size:23px}.item{grid-template-columns:1fr auto}.item .meta{grid-row:2;grid-column:1/-1}.panel{padding:13px}h1{font-size:21px}}';
const loginScript="(()=>{const pw=document.getElementById('pw'),b=document.getElementById('pw-toggle'),otp=document.getElementById('otp'),form=document.getElementById('owner-login'),submit=document.getElementById('login-submit'),status=document.getElementById('login-status');if(!pw||!b||!otp||!form||!submit||!status)return;const normalize=s=>s.replace(/[٠-٩۰-۹]/g,d=>String(d.charCodeAt(0)%16)).replace(/\\s/g,'');const message=(s,error)=>{status.textContent=s;status.className=error?'warn':'login-progress';status.hidden=false;};b.hidden=false;b.addEventListener('click',()=>{const show=pw.type==='password';pw.type=show?'text':'password';b.textContent=show?'إخفاء':'إظهار';b.setAttribute('aria-pressed',String(show));});otp.addEventListener('input',()=>{otp.value=normalize(otp.value);});form.noValidate=true;let sending=false;form.addEventListener('submit',e=>{if(sending){e.preventDefault();return;}otp.value=normalize(otp.value);if(!pw.value||pw.value.length>256){e.preventDefault();message('أدخل كلمة المرور الصحيحة أولًا.',true);pw.focus();return;}if(!/^[0-9]{6}$/.test(otp.value)){e.preventDefault();message('أدخل رمز المصادقة المكون من 6 أرقام دون مسافات.',true);otp.focus();return;}sending=true;pw.type='password';b.textContent='إظهار';b.setAttribute('aria-pressed','false');message('جارٍ التحقق من بيانات الدخول…',false);submit.textContent='جارٍ التحقق…';submit.setAttribute('aria-busy','true');});window.addEventListener('pageshow',()=>{sending=false;submit.textContent='دخول آمن';submit.removeAttribute('aria-busy');status.hidden=true;});})();";
const loginScriptHash=crypto.createHash('sha256').update(loginScript,'utf8').digest('base64');
const dashboardCss=".workspace{display:grid;grid-template-columns:220px minmax(0,1fr);gap:18px;align-items:start;min-width:0}.workspace main{min-width:0;padding:0;width:100%}.workspace-nav{position:sticky;top:14px;background:#142e45;border-radius:12px;padding:14px;color:white}.workspace-nav h2{font-size:16px;color:#edc77e;margin:0 0 12px}.workspace-nav a{display:flex;align-items:center;gap:10px;padding:10px 12px;color:#e7eef5;text-decoration:none;border-radius:7px;margin-bottom:4px;font-weight:bold}.workspace-nav a[aria-current=\"page\"]{background:#31536b;color:white}.workspace-nav a:hover{background:#29465d}.workspace-nav small{display:block;border-top:1px solid #39556b;padding-top:10px;margin-top:12px;color:#d5e2ed}.workspace-nav .nav-icon{color:#edc77e;font-size:18px}.workspace-content{min-width:0}.workspace-content [hidden]{display:none!important}.dash-title{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:8px;margin-bottom:12px}.dash-title h1{font-size:24px}.session-info{border:1px solid #cbd9e4;border-radius:8px;background:#fff;padding:7px 12px;font-size:12px;color:#29465d;white-space:nowrap}.metric{display:block;text-decoration:none;color:#182b3e;border-right:4px solid #64748b}.metric[data-platform=\"github\"]{border-right-color:#334155}.metric[data-platform=\"vercel\"]{border-right-color:#2563eb}.metric[data-platform=\"supabase\"]{border-right-color:#15803d}.metric:hover{background:#f9fbff;border-top-color:#8ba8c0}.metric .meta{font-size:12px}.metric b{font-size:32px;line-height:1.3}.products .project{background:#fbfcfe;display:flex;flex-direction:column;gap:6px;min-width:0}.products .project .links{margin-top:auto}.project .badge{align-self:flex-start}.filter-bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:12px 0}.filter-bar input{flex:1;min-width:120px;border:1px solid #bfcfda;padding:10px;border-radius:7px;font:inherit;background:white;color:#182b3e}.inventory-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}.inventory-head h2{margin:0}.inventory-row{border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) auto}.inventory-row:last-child{border:1px solid #e2e8f0}.inventory-row a{border:1px solid #d5dfe7;border-radius:6px;padding:5px 9px;text-decoration:none;font-size:13px;white-space:nowrap}.snapshot-note{border-right:3px solid #b77924;padding:10px 12px;background:#fff9ed;color:#745019;border-radius:7px;font-size:13px;margin:12px 0}.workspace-footer{border-top:1px solid #d5dfe7;color:#4b6073;font-size:12px;padding:10px 0;margin-top:14px}.admin-brand{display:flex;gap:10px;align-items:center}.admin-brand svg{flex:0 0 32px}.workspace main{margin:0}.workspace-content section{scroll-margin-top:14px}@media(min-width:1000px){body.owner-dashboard>main{width:min(1600px,100%);padding:18px 24px}}@media(max-width:760px){.workspace{grid-template-columns:minmax(0,1fr);gap:10px}.workspace-nav{position:static;display:flex;flex-wrap:wrap;gap:5px;padding:8px}.workspace-nav h2,.workspace-nav small{display:none}.workspace-nav a{font-size:12px;padding:7px 8px;margin:0;flex:1 1 auto;justify-content:center}.workspace-nav .nav-icon{font-size:15px}.workspace-content .metrics{gap:7px}.metric{padding:10px}.metric b{font-size:25px}.metric p{font-size:12px}.inventory-row{grid-template-columns:minmax(0,1fr) auto}.inventory-row .meta{grid-row:2;grid-column:1/-1}.dash-title h1{font-size:20px}.session-info{white-space:normal}.filter-bar{gap:6px}}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto!important;transition:none!important}}";
const dashboardScript="(()=>{const root=document.getElementById('workspace'),search=document.getElementById('inventory-search'),count=document.getElementById('inventory-count'),session=document.getElementById('session-time');if(!root)return;const views=[...root.querySelectorAll('[data-view]')],nav=[...root.querySelectorAll('[data-nav]')],normalize=s=>String(s).normalize('NFKD').toLowerCase().replace(/[\\u064b-\\u065f\\u0670]/g,'').replace(/[أإآ]/g,'ا').trim();let current='overview';function filter(){const view=views.find(v=>v.dataset.view===current);if(!view)return;const q=normalize(search.value),rows=[...view.querySelectorAll('[data-record]')];let visible=0;for(const row of rows){row.hidden=!!q&&!normalize(row.textContent).includes(q);if(!row.hidden)visible++;}count.textContent=rows.length?visible+' / '+rows.length:'';const empty=view.querySelector('[data-empty]');if(empty)empty.hidden=visible!==0;}function route(){const key=location.hash.slice(1);current=views.some(v=>v.dataset.view===key)?key:'overview';for(const view of views)view.hidden=view.dataset.view!==current;for(const a of nav){if(a.dataset.nav===current)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current');}search.value='';filter();}search.addEventListener('input',filter);window.addEventListener('hashchange',route);route();if(session){const expiry=Number(session.dataset.expires)*1000;function tick(){const remain=Math.max(0,Math.ceil((expiry-Date.now())/1000));session.textContent='الجلسة: '+Math.floor(remain/60)+':'+String(remain%60).padStart(2,'0');if(remain===0){location.replace('/admin');return false;}return true;}if(tick()){const timer=setInterval(()=>{if(!tick())clearInterval(timer);},1000);window.addEventListener('pageshow',tick);}}})();";
const dashboardScriptHash=crypto.createHash('sha256').update(dashboardScript,'utf8').digest('base64');
function shell(content,logged=false){
 return '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow,noarchive"><title>WAJHAT | الإدارة الداخلية</title><style>'+css+dashboardCss+'</style></head><body'+(logged?' class="owner-dashboard"':'')+'><header><div class="admin-brand"><svg aria-hidden="true" width="32" height="32" viewBox="0 0 48 48"><path fill="#909090" d="M1 1h22v22H1z"/><path fill="#d89050" d="M25 1h22v22H25z"/><path fill="#606060" d="M1 25h22v22H1z"/><path fill="#b06020" d="M25 25h22v22H25z"/></svg><div><b>واجهات | WAJHAT</b><br><small>الإدارة الداخلية</small></div></div>'+'<div class="admin-nav"><a class="btn home-link" href="/">العودة للموقع</a>'+(logged?'<form method="post" action="/admin"><input type="hidden" name="action" value="logout"><button type="submit">تسجيل الخروج</button></form>':'')+'</div>'+'</header><main>'+content+'</main></body></html>';
}
function login(message){return shell('<section class="panel login"><h1>دخول المالك</h1><p>لوحة خاصة — التحقق الثنائي مطلوب.</p>'+(message?'<div class="warn" role="alert">'+esc(message)+'</div>':'')+'<form id="owner-login" method="post" action="/admin"><input type="hidden" name="action" value="login"><label for="pw">كلمة المرور</label><div class="pw-wrap"><input id="pw" type="password" name="password" autocomplete="current-password" required maxlength="256"><button id="pw-toggle" type="button" aria-controls="pw" aria-pressed="false" hidden>إظهار</button></div><label for="otp">رمز تطبيق المصادقة</label><input id="otp" name="otp" type="text" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9٠-٩۰-۹]{6}" minlength="6" maxlength="12" required><p id="login-status" role="status" aria-live="polite" hidden></p><button id="login-submit" type="submit">دخول آمن</button></form></section><script>'+loginScript+'</script>')}
function readInventory(){try{const d=JSON.parse(process.env.WAJHAT_ADMIN_INVENTORY||'null');if(!d||!['github','vercel','supabase','products'].every(k=>Array.isArray(d[k])))return null;return d}catch{return null}}
function dashboard(d,expires){
 if(!d)return shell('<section class="panel"><h1>لوحة الإدارة</h1><div class="warn">سجل المشاريع غير مهيأ. لا توجد بيانات معروضة.</div></section>',true);
 const groups=[['github','GitHub','المستودعات','◈'],['vercel','Vercel','الاستضافة','▲'],['supabase','Supabase','قواعد البيانات','▣']];
 const link=(label,url)=>{const u=safeLink(url);return u?'<a href="'+esc(u)+'" target="_blank" rel="noopener noreferrer">'+esc(label)+'</a>':''};
 const metrics=groups.map(([k,n,l])=>'<a class="metric" data-platform="'+k+'" href="#'+k+'"><span class="meta">'+esc(n)+'</span><b>'+d[k].length+'</b><p>'+esc(l)+'</p></a>').join('');
 const products=d.products.map(p=>'<article class="project" data-record><h3>'+esc(p.name)+'</h3><span class="badge">'+esc(p.status)+'</span><p>'+esc(p.next)+'</p><div class="links">'+(Array.isArray(p.links)?p.links.map(l=>link(l.label,l.url)).join(''):'')+'</div></article>').join('');
 const overview='<section data-view="overview" id="overview"><div class="metrics">'+metrics+'</div><div class="panel"><h2>المشاريع ذات الأولوية</h2><div class="products">'+products+'</div><p data-empty hidden>لا توجد نتائج مطابقة.</p><p class="footer">الحالات حسب آخر قرار إداري، وليست نتيجة فحص حي.</p></div></section>';
 const tables=groups.map(([k,n,l])=>'<section class="panel" data-view="'+k+'" id="'+k+'"><div class="inventory-head"><h2>'+esc(n)+' — '+esc(l)+'</h2><span class="badge">'+d[k].length+' مشروع</span></div><div class="list">'+d[k].map(p=>'<div class="item inventory-row" data-record><span class="name" dir="ltr">'+esc(p.name)+'</span><span class="meta">'+esc(p.account)+' · '+esc(p.status)+'</span>'+link('فتح المشروع',p.url)+'</div>').join('')+'</div><p data-empty hidden>لا توجد نتائج مطابقة.</p></section>').join('');
 const nav='<aside class="workspace-nav" aria-label="أقسام لوحة القيادة"><h2>مركز القيادة</h2><a data-nav="overview" href="#overview"><span class="nav-icon" aria-hidden="true">▦</span>نظرة عامة</a>'+groups.map(([k,n,l,i])=>'<a data-nav="'+k+'" href="#'+k+'"><span class="nav-icon" aria-hidden="true">'+i+'</span>'+esc(n)+'</a>').join('')+'<small>صلاحية المالك · قراءة فقط</small></aside>';
 return shell('<div class="workspace" id="workspace">'+nav+'<div class="workspace-content"><div class="dash-title"><h1>مركز التحكم بالمشاريع</h1><span class="session-info" id="session-time" data-expires="'+esc(expires)+'">جلسة آمنة · 15 دقيقة</span></div><p>آخر حصر: <bdi>'+esc(d.asOf)+'</bdi> · حساب المالك</p><div class="snapshot-note">البيانات حصر مؤرخ، وليست مزامنة لحظية. لا تتضمن مفاتيح API أو كلمات مرور.</div><div class="filter-bar"><label for="inventory-search">بحث</label><input id="inventory-search" type="search" placeholder="اسم المشروع، الحساب أو الحالة" autocomplete="off"><span id="inventory-count" aria-live="polite"></span></div>'+overview+tables+'<div class="workspace-footer">WAJHAT CONTROL CENTER · v2.0.0 · قراءة فقط · لا توجد أوامر نقل أو حذف</div></div></div><script>'+dashboardScript+'</script>',true);
}
function headers(res){res.setHeader('Content-Type','text/html; charset=utf-8');res.setHeader('Cache-Control','private, no-store, max-age=0');res.setHeader('Pragma','no-cache');res.setHeader('Vercel-CDN-Cache-Control','no-store');res.setHeader('X-Robots-Tag','noindex, nofollow, noarchive');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','same-origin');res.setHeader('Strict-Transport-Security','max-age=31536000');res.setHeader('Cross-Origin-Opener-Policy','same-origin');res.setHeader('Cross-Origin-Resource-Policy','same-origin');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');res.setHeader('Content-Security-Policy',"default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-"+loginScriptHash+"' 'sha256-"+dashboardScriptHash+"'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")}
function send(res,status,body){res.statusCode=status;res.end(body)}
function parse(req){
 if(!/^application\/x-www-form-urlencoded(?:;|$)/i.test(String(req.headers['content-type']||'')))return null;
 const declared=Number(req.headers['content-length']||0);if(!Number.isFinite(declared)||declared<0||declared>MAX)return null;
 let data;
 if(typeof req.body==='string'){if(Buffer.byteLength(req.body)>MAX)return null;const q=new URLSearchParams(req.body);data=Object.create(null);for(const [k,v] of q){if(Object.hasOwn(data,k))return null;data[k]=v;}}
 else if(req.body&&typeof req.body==='object'&&!Buffer.isBuffer(req.body))data=req.body;else return null;
 const keys=Object.keys(data);if(!keys.length||keys.some(k=>!['action','password','otp'].includes(k)||typeof data[k]!=='string'))return null;
 if(keys.reduce((n,k)=>n+Buffer.byteLength(k)+Buffer.byteLength(data[k]),0)>MAX)return null;
 if(data.action==='logout'&&keys.length!==1)return null;
 return data;
}
function handler(req,res){
 headers(res);const cfg=config(res);
 if(!cfg)return send(res,503,shell('<section class="panel login"><h1>لوحة الإدارة غير مفعلة</h1><p>يجب إكمال إعداد بيانات المصادقة على الخادم أولًا. لا تُعرض أي بيانات قبل التفعيل.</p></section>'));
 if(req.method==='GET'||req.method==='HEAD'){const token=cookie(req);return send(res,200,req.method==='HEAD'?'':verify(cfg.key,token)?dashboard(readInventory(),JSON.parse(Buffer.from(token.split('.')[0],'base64url').toString('utf8')).exp):login());}
 if(req.method!=='POST'){res.setHeader('Allow','GET, HEAD, POST');return send(res,405,shell('<p>الطلب غير مسموح.</p>'))}
 if(!sameOrigin(req))return send(res,403,shell('<p>الطلب غير مسموح.</p>'));
 const data=parse(req);if(!data)return send(res,400,login('طلب غير صالح.'));
 if(data.action==='logout'){setCookie(res,'',0);res.statusCode=303;res.setHeader('Location','/admin');return res.end()}
 if(data.action!=='login'||typeof data.password!=='string'||data.password.length>256||typeof data.otp!=='string')return send(res,400,login('طلب غير صالح.'));
 if(!throttle(req)){res.setHeader('Retry-After','300');return send(res,429,login('محاولات كثيرة. حاول لاحقًا.'))}
 const normalizedOtp=data.otp.trim().replace(/[٠-٩۰-۹]/g,d=>String(d.charCodeAt(0)%16));
 const okPass=validPassword(cfg,data.password),okOtp=validOtp(cfg.secret,normalizedOtp);
 if(!okPass||!okOtp){
  // Preview-only private diagnostics: no credential contents or public distinction.
  if(process.env.VERCEL_ENV==='preview')console.warn('WAJHAT_ADMIN_AUTH_REJECTED: '+(!okPass?'password_rejected':'otp_rejected'));
  return send(res,401,login('تعذر تسجيل الدخول. تحقق من بيانات المصادقة.'));
 }
 setCookie(res,issue(cfg.key),TTL);res.statusCode=303;res.setHeader('Location','/admin');return res.end();
}
module.exports=handler;
