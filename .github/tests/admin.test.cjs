'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const mod=require.resolve('../../api/admin.js');
// Synthetic test fixtures only; these are not real credentials or project data.
const pw='test-fixture-not-a-real-password-1234',seed='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',secret=Buffer.from('12345678901234567890');
const salt=Buffer.alloc(16,17),key=Buffer.alloc(32,23),authConfig=JSON.stringify({v:1,salt:salt.toString('hex'),verifier:crypto.pbkdf2Sync(pw,salt,600000,32,'sha256').toString('hex'),sessionKey:key.toString('hex'),totp:seed});
const fixture={asOf:'2026-11-27',github:[{name:'PRIVATE_TEST_RECORD <script>',account:'test',status:'private',url:'https://github.com/example/example'}],vercel:[],supabase:[],products:[{name:'Test project',status:'test',next:'test only',links:[{label:'dangerous',url:'javascript:alert(1)'}]}]};
function fresh(configured=true){
 for(const k of ['WAJHAT_ADMIN_AUTH','WAJHAT_ADMIN_INVENTORY','WAJHAT_ADMIN_PASSWORD'])delete process.env[k];
 process.env.WAJHAT_ADMIN_INVENTORY=JSON.stringify(fixture);
 if(configured)process.env.WAJHAT_ADMIN_AUTH=authConfig
 delete require.cache[mod];return require(mod);
}
function otp(){const buf=Buffer.alloc(8);buf.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const mac=crypto.createHmac('sha1',secret).update(buf).digest();return String((mac.readUInt32BE(mac[19]&15)&0x7fffffff)%1000000).padStart(6,'0')}
function call(handler,{method='GET',headers={},body,url='/admin'}={}){
 const req={method,url,headers:{host:'www.wajhat.co',...headers},body};
 const out={headers:{},statusCode:200,body:'',setHeader(k,v){this.headers[k.toLowerCase()]=v},end(b){this.body=b||''}};
 handler(req,out);return out;
}
const formHeaders={origin:'https://www.wajhat.co','content-type':'application/x-www-form-urlencoded'};
const auth=()=>({action:'login',password:pw,otp:otp()});
function login(h){const r=call(h,{method:'POST',headers:formHeaders,body:auth()});assert.equal(r.statusCode,303);return r.headers['set-cookie'].split(';')[0]}
test('missing authentication config fails closed, even when private inventory exists',()=>{const r=call(fresh(false));assert.equal(r.statusCode,503);assert.doesNotMatch(r.body,/PRIVATE_TEST_RECORD/);assert.match(r.headers['cache-control'],/no-store/)});
test('unauthenticated GET and direct API do not disclose data',()=>{const h=fresh();for(const url of ['/admin','/api/admin']){const r=call(h,{url});assert.equal(r.statusCode,200);assert.match(r.body,/كلمة المرور/);assert.doesNotMatch(r.body,/PRIVATE_TEST_RECORD/);assert.match(r.headers['x-robots-tag'],/noindex/)}});
test('valid password and OTP issue secure cookie and private page',()=>{const h=fresh();const r=call(h,{method:'POST',headers:formHeaders,body:auth()});assert.equal(r.statusCode,303);assert.match(r.headers['set-cookie'],/HttpOnly; Secure; SameSite=Strict/);const a=call(h,{headers:{cookie:r.headers['set-cookie'].split(';')[0]}});assert.match(a.body,/PRIVATE_TEST_RECORD &lt;script&gt;/);assert.doesNotMatch(a.body,/javascript:alert/);assert.match(a.headers['content-security-policy'],/frame-ancestors 'none'/)});
test('password and OTP each required',()=>{const h=fresh();for(const body of [{...auth(),password:'wrong'},{...auth(),otp:'bad'}]){const r=call(h,{method:'POST',headers:formHeaders,body});assert.equal(r.statusCode,401);assert.equal(r.headers['set-cookie'],undefined);assert.doesNotMatch(r.body,/PRIVATE_TEST_RECORD/)}});
test('cross-origin login and unsupported methods denied',()=>{const h=fresh();assert.equal(call(h,{method:'POST',headers:{...formHeaders,origin:'https://evil.example'},body:auth()}).statusCode,403);assert.equal(call(h,{method:'PUT'}).statusCode,405)});
test('tampered or expired cookie is denied',()=>{const h=fresh(),cookie=login(h);const tampered=cookie.slice(0,-1)+(cookie.endsWith('A')?'B':'A');assert.doesNotMatch(call(h,{headers:{cookie:tampered}}).body,/PRIVATE_TEST_RECORD/);const now=Math.floor(Date.now()/1000);const payload=Buffer.from(JSON.stringify({v:1,iat:now-901,exp:now-1,n:'a'.repeat(32)})).toString('base64url');const sig=crypto.createHmac('sha256',key).update(payload).digest('base64url');assert.doesNotMatch(call(h,{headers:{cookie:'__Host-wajhat_admin='+payload+'.'+sig}}).body,/PRIVATE_TEST_RECORD/)});
test('logout clears cookie, POST without correct origin denied',()=>{const h=fresh(),cookie=login(h);const r=call(h,{method:'POST',headers:{...formHeaders,cookie},body:{action:'logout'}});assert.equal(r.statusCode,303);assert.match(r.headers['set-cookie'],/Max-Age=0/);assert.equal(call(h,{method:'POST',headers:{cookie},body:{action:'logout'}}).statusCode,403)});
test('per-instance throttle denies sixth attempt',()=>{const h=fresh();for(let i=0;i<5;i++)assert.equal(call(h,{method:'POST',headers:formHeaders,body:{...auth(),password:'wrong'}}).statusCode,401);assert.equal(call(h,{method:'POST',headers:formHeaders,body:auth()}).statusCode,429)});

test('explicit hex prefix and valid longer salt preserve exact PBKDF2 bytes',()=>{
 for(const [raw,encoded] of [[salt,'0x'+salt.toString('hex')],[Buffer.alloc(17,41),Buffer.alloc(17,41).toString('hex')]]){
  const h=fresh(),v=JSON.parse(authConfig);
  v.salt=encoded;v.verifier=crypto.pbkdf2Sync(pw,raw,600000,32,'sha256').toString('hex');
  process.env.WAJHAT_ADMIN_AUTH=JSON.stringify(v);
  assert.equal(call(h).statusCode,200);
  assert.match(call(h,{headers:{cookie:login(h)}}).body,/PRIVATE_TEST_RECORD/);
 }
});
test('short or malformed salt remains fail closed',()=>{
 const h=fresh(),v=JSON.parse(authConfig);for(const invalid of ['00','z'+salt.toString('hex')+'z']){
  v.salt=invalid;process.env.WAJHAT_ADMIN_AUTH=JSON.stringify(v);
  assert.equal(call(h).statusCode,503);
 }
});

test('owner password rotation retains OTP, denies old password and invalidates existing cookies',()=>{
 const h=fresh(),cookie=login(h),next='new-synthetic-password-fixture-1234',s=Buffer.alloc(16,55);
 process.env.WAJHAT_ADMIN_PASSWORD=JSON.stringify({v:1,salt:s.toString('hex'),verifier:crypto.pbkdf2Sync(next,s,600000,32,'sha256').toString('hex')});
 assert.doesNotMatch(call(h,{headers:{cookie}}).body,/PRIVATE_TEST_RECORD/);
 assert.equal(call(h,{method:'POST',headers:formHeaders,body:auth()}).statusCode,401);
 assert.equal(call(h,{method:'POST',headers:formHeaders,body:{...auth(),password:next,otp:'bad'}}).statusCode,401);
 const r=call(h,{method:'POST',headers:formHeaders,body:{...auth(),password:next}});
 assert.equal(r.statusCode,303);
 assert.match(call(h,{headers:{cookie:r.headers['set-cookie'].split(';')[0]}}).body,/PRIVATE_TEST_RECORD/);
});
test('invalid password rotation fails closed',()=>{const h=fresh();process.env.WAJHAT_ADMIN_PASSWORD='invalid';assert.equal(call(h).statusCode,503)});

test('browser form referrer policy preserves same-origin POST, blocks foreign or opaque origins',()=>{
 const h=fresh(),get=call(h);
 assert.equal(get.headers['referrer-policy'],'same-origin');
 for(const origin of ['null','https://evil.example',undefined]){
  const r=call(h,{method:'POST',headers:{...formHeaders,origin},body:auth()});
  assert.equal(r.statusCode,403);assert.equal(r.headers['set-cookie'],undefined);
 }
 assert.equal(call(h,{method:'POST',headers:formHeaders,body:auth()}).statusCode,303);
});

test('password visibility toggle has a narrowly scoped CSP hash and never submits the form',()=>{
 const r=call(fresh());
 assert.match(r.body,/id="pw" type="password"/);
 assert.match(r.body,/id="pw-toggle" type="button" aria-controls="pw"/);
 const script=r.body.match(/<script>([\s\S]*?)<\/script>/)[1];
 const hash=crypto.createHash('sha256').update(script).digest('base64');
 assert.ok(r.headers['content-security-policy'].includes("script-src 'sha256-"+hash+"'"));
 assert.ok(!r.headers['content-security-policy'].includes("script-src 'unsafe-inline'"));

 const listeners={},pwField={type:'password',value:'',focus(){}},button={hidden:true,textContent:'إظهار',setAttribute(){},addEventListener(n,fn){listeners[n]=fn}},otpField={value:'',focus(){},addEventListener(n,fn){listeners[n]=fn}},form={addEventListener(n,fn){listeners[n]=fn}},submit={setAttribute(){},removeAttribute(){}},status={hidden:true};
 require('node:vm').runInNewContext(script,{document:{getElementById:id=>({'pw':pwField,'pw-toggle':button,'otp':otpField,'owner-login':form,'login-submit':submit,'login-status':status}[id])},window:{addEventListener(){}}});
 assert.equal(button.hidden,false);listeners.click();assert.equal(pwField.type,'text');listeners.click();assert.equal(pwField.type,'password');
 otpField.value='١٢٣ ۴۵۶';listeners.input();assert.equal(otpField.value,'123456');
 let prevented=false;const event={preventDefault(){prevented=true}};
 listeners.submit(event);assert.equal(prevented,true);assert.match(status.textContent,/كلمة المرور/);
 pwField.value='synthetic-password';otpField.value='12';prevented=false;listeners.submit(event);assert.equal(prevented,true);assert.match(status.textContent,/6 أرقام/);
 otpField.value='123456';prevented=false;listeners.submit(event);assert.equal(prevented,false);assert.match(status.textContent,/التحقق/);assert.equal(submit.textContent,'جارٍ التحقق…');
 prevented=false;listeners.submit(event);assert.equal(prevented,true);

});
test('Arabic and Persian OTP digits are normalized without changing password',()=>{
 for(const base of [0x660,0x6f0]){
  const h=fresh(),localized=otp().replace(/[0-9]/g,d=>String.fromCharCode(base+Number(d)));
  const r=call(h,{method:'POST',headers:formHeaders,body:{...auth(),otp:localized}});
  assert.equal(r.statusCode,303);
 }
});
