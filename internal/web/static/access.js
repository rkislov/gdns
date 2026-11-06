// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0
'use strict';
let identity={username:'',role:'viewer',source:''},csrf='',accessConfig=null,accessETag='';
function loginMode(){const source=$('#login-source').value;$('#token-login').classList.toggle('hidden',source!=='token');$('#password-login').classList.toggle('hidden',source==='token')}
async function initLogin(){
 $('#login-source').onchange=loginMode;
 try{const info=await fetch('/api/auth/info',{credentials:'same-origin'}).then(r=>r.json());document.querySelector('#login-source option[value="ldap"]').disabled=!info.domain_enabled;if(!info.password_login)$('#login-source').value='token'}catch{}
 loginMode();try{await start(true)}catch{}
}
async function login(event){
 event.preventDefault();$('#login-error').textContent='';const button=event.target.querySelector('button');button.disabled=true;
 try{
  const source=$('#login-source').value;
  if(source==='token'){token=$('#token').value.trim();csrf=''}else{
   token='';csrf='';sessionStorage.removeItem('gdns-token');await api('auth/login',{method:'POST',body:JSON.stringify({source,username:$('#username').value.trim(),password:$('#password').value})})
  }
  await start();$('#password').value='';$('#token').value='';
 }catch(e){$('#login-error').textContent=e.message}finally{button.disabled=false}
}
async function logout(){try{await api('auth/logout',{method:'POST'})}catch{}sessionStorage.removeItem('gdns-token');token='';csrf='';location.reload()}
function applyPermissions(){
 if(identity.role!=='admin'){
  for(const selector of ['[data-action="new-feed"]','[data-action="edit-feed"]','[data-action="delete-feed"]','[data-action="refresh-rfc5011"]'])document.querySelectorAll(selector).forEach(e=>e.classList.add('hidden'));
 }
 if(identity.role==='viewer'){
  document.querySelectorAll('#content button').forEach(e=>{if(!['logs-refresh','logs-next','logs-prev','export'].includes(e.dataset.action))e.classList.add('hidden')});
  document.querySelectorAll('#content textarea').forEach(e=>e.readOnly=true);
 }
}
const roleName=r=>({admin:'Администратор',operator:'Оператор зон',viewer:'Просмотр'}[r]||r);
function ldapBody(){return {enabled:$('#ad-enabled').checked,url:$('#ad-url').value.trim(),start_tls:$('#ad-starttls').checked,ca_file:$('#ad-ca').value.trim(),bind_dn:$('#ad-bind').value.trim(),bind_password:$('#ad-password').value,base_dn:$('#ad-base').value.trim(),user_filter:$('#ad-filter').value.trim(),group_attribute:$('#ad-attribute').value.trim(),timeout_seconds:Number($('#ad-timeout').value),groups:['admin','operator','viewer'].flatMap(role=>lines($('#ad-groups-'+role).value).map(dn=>({dn,role})))}}
async function accessRequest(path,method,body){return api(path,{method,headers:{'If-Match':accessETag},...(body?{body:JSON.stringify(body)}:{})})}
async function loadAccess(){const r=await fetch('/api/access',{credentials:'same-origin',headers:token?{Authorization:'Bearer '+token}:{}});if(!r.ok)throw Error(await r.text());accessETag=r.headers.get('ETag')||'';accessConfig=await r.json()}
async function renderAccess(){
 $('#content').innerHTML='<div class="card"><p>Загрузка настроек доступа…</p></div>';
 try{
  if(identity.role==='admin')await loadAccess();if(tab!=='access')return;
  let html=`<section class="card mb-5"><h2>Текущая учётная запись</h2><p class="mt-3">${esc(identity.username)} · ${esc(roleName(identity.role))} · ${esc(identity.source)}</p></section>`;
  if(identity.source==='local')html+=`<form id="password-form" class="card mb-5 max-w-2xl space-y-4"><h2>Изменить свой пароль</h2><div><label>Текущий пароль</label><input id="own-current" type="password" autocomplete="current-password" required></div><div><label>Новый пароль · не менее 12 символов</label><input id="own-password" type="password" autocomplete="new-password" minlength="12" maxlength="1024" required></div><button class="btn">Сменить пароль</button></form>`;
  if(identity.role==='admin'){
   const c=accessConfig,ad=c.ldap;
   html+=`<section class="card mb-5"><h2>Локальные пользователи</h2><p class="text-sm text-muted mt-2">Оператор управляет зонами, ручным списком блокировки и обновлением фидов. Настройки сервера и доступа доступны администратору. Последнего локального администратора удалить или отключить нельзя.</p><div class="overflow-x-auto"><table class="w-full mt-4 text-sm text-left"><thead><tr><th>Имя</th><th>Роль</th><th>Статус</th><th></th></tr></thead><tbody>${c.users.map(u=>`<tr class="border-t border-slate-100"><td class="py-3">${esc(u.username)}</td><td>${esc(roleName(u.role))}</td><td>${u.disabled?'Отключён':'Активен'}</td><td class="text-right"><button class="secondary" data-user-edit="${esc(u.username)}">Изменить</button> <button class="danger" data-user-delete="${esc(u.username)}">Удалить</button></td></tr>`).join('')}</tbody></table></div></section><form id="user-form" class="card mb-5 space-y-4 max-w-2xl"><h2>Добавить или изменить пользователя</h2><div><label>Имя · латиница, цифры, . _ @ -</label><input id="user-name" maxlength="64" autocomplete="off" required></div><div><label>Пароль · пусто сохраняет пароль существующего пользователя</label><input id="user-password" type="password" minlength="12" maxlength="1024" autocomplete="new-password"></div><div><label>Роль</label><select id="user-role">${['admin','operator','viewer'].map(r=>`<option value="${r}">${roleName(r)}</option>`).join('')}</select></div><label class="flex gap-3 items-center"><input id="user-disabled" type="checkbox" class="w-4">Отключить вход</label><button class="btn">Сохранить пользователя</button></form>`;
   html+=`<form id="ldap-form" class="card space-y-4 max-w-4xl"><h2>Домен · LDAP / Active Directory</h2><label class="flex gap-3 items-center"><input id="ad-enabled" type="checkbox" class="w-4" ${ad.enabled?'checked':''}>Разрешить доменный вход</label><div class="grid md:grid-cols-2 gap-4"><div><label>LDAP URL</label><input id="ad-url" value="${esc(ad.url)}" placeholder="ldaps://dc.example.org:636"></div><div><label>Доверенный CA · путь на сервере</label><input id="ad-ca" value="${esc(ad.ca_file)}" placeholder="/etc/gdns/ldap-ca.pem"></div></div><label class="flex gap-3 items-center"><input id="ad-starttls" type="checkbox" class="w-4" ${ad.start_tls?'checked':''}>StartTLS для ldap:// (обычно порт 389)</label><div><label>Сервисная учётная запись · Bind DN / UPN</label><input id="ad-bind" value="${esc(ad.bind_dn)}" autocomplete="off"></div><div><label>Пароль сервисной учётной записи</label><input id="ad-password" type="password" value="${esc(ad.bind_password)}" autocomplete="new-password"><p class="text-xs text-muted mt-1">*** сохраняет существующий пароль.</p></div><div><label>Base DN</label><input id="ad-base" value="${esc(ad.base_dn)}" placeholder="DC=example,DC=org"></div><div><label>Фильтр пользователя · {username} экранируется сервером</label><input id="ad-filter" value="${esc(ad.user_filter||'(sAMAccountName={username})')}"></div><div class="grid md:grid-cols-2 gap-4"><div><label>Атрибут групп</label><input id="ad-attribute" value="${esc(ad.group_attribute||'memberOf')}"></div><div><label>Тайм-аут · секунды</label><input id="ad-timeout" type="number" min="1" max="30" value="${ad.timeout_seconds||5}"></div></div>${['admin','operator','viewer'].map(role=>`<div><label>Группы: ${roleName(role)} · полный DN, по одной в строке</label><textarea id="ad-groups-${role}" rows="2" class="mono">${esc((ad.groups||[]).filter(g=>g.role===role).map(g=>g.dn).join('\n'))}</textarea></div>`).join('')}<p class="text-xs text-muted">Используются прямые значения memberOf. Если подходят несколько групп, выбирается старшая роль. Локальная учётная запись имеет приоритет при совпадении имени. Пароль доменного пользователя не сохраняется; TLS-сертификат контроллера проверяется.</p><button class="btn">Сохранить LDAP</button><div class="border-t border-slate-100 pt-5"><label>Проверить поиск пользователя и группы</label><input id="ad-test-name" placeholder="имя пользователя"><button id="ad-test" type="button" class="secondary mt-3">Проверить соединение</button><pre id="ad-test-result" class="text-xs whitespace-pre-wrap mt-3"></pre></div></form>`;
  }
  $('#content').innerHTML=html;
  const own=$('#password-form');if(own)own.onsubmit=e=>{e.preventDefault();attempt(async()=>{await api('auth/password',{method:'POST',body:JSON.stringify({current_password:$('#own-current').value,password:$('#own-password').value})});sessionStorage.removeItem('gdns-token');location.reload()})};
  const user=$('#user-form');if(user)user.onsubmit=e=>{e.preventDefault();attempt(async()=>{await accessRequest('access/users','POST',{username:$('#user-name').value.trim(),password:$('#user-password').value,role:$('#user-role').value,disabled:$('#user-disabled').checked});await renderAccess();notice('Пользователь сохранён.')})};
  const form=$('#ldap-form');if(form)form.onsubmit=e=>{e.preventDefault();attempt(async()=>{await accessRequest('access/ldap','PUT',ldapBody());await renderAccess();notice('Настройки доменного входа сохранены.')})};
  const test=$('#ad-test');if(test)test.onclick=()=>attempt(async()=>{test.disabled=true;try{const r=await api('access/ldap/test',{method:'POST',body:JSON.stringify({ldap:ldapBody(),username:$('#ad-test-name').value.trim()})});$('#ad-test-result').textContent=JSON.stringify(r,null,2)}finally{test.disabled=false}});
  document.querySelectorAll('[data-user-edit]').forEach(b=>b.onclick=()=>{const u=accessConfig.users.find(x=>x.username===b.dataset.userEdit);$('#user-name').value=u.username;$('#user-role').value=u.role;$('#user-disabled').checked=u.disabled;$('#user-password').value='';$('#user-form').scrollIntoView({behavior:'smooth'})});
  document.querySelectorAll('[data-user-delete]').forEach(b=>b.onclick=()=>{if(confirm('Удалить пользователя '+b.dataset.userDelete+'?'))attempt(async()=>{await accessRequest('access/users?username='+encodeURIComponent(b.dataset.userDelete),'DELETE');await renderAccess()})});
 }catch(e){if(tab==='access')$('#content').innerHTML=`<div class="card text-red-700">${esc(e.message)}</div>`}
}
