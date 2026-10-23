// @ts-check
// Recruitment records share wallet authentication, never financial permissions.
import {createHash, randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';

const fail = (code, status = 400) => Object.assign(new Error(code), {code, status});
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => JSON.stringify(value, (_, item) => item && typeof item === 'object' && !Array.isArray(item) ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
const ROLES = new Set(['compute', 'reproduce', 'evaluate', 'develop', 'curate']);
const STATUSES = new Set(['submitted', 'reviewing', 'waitlisted', 'selected', 'rejected', 'withdrawn']);
const ACTIVE = "('submitted','reviewing','waitlisted','selected')";
export const RECRUITMENT_CONSENT = 'project-coordination-v1';

function object(value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(key => !allowed.includes(key))) throw fail('project_invalid_fields');
  return value;
}
function text(value, max, required = false) {
  if (value === undefined || value === null || value === '') { if (required) throw fail('project_required_field'); return null; }
  if (typeof value !== 'string' || value.length > max || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value) || (required && !value.trim())) throw fail('project_invalid_text');
  return value.trim() || null;
}
function number(value, min, max, integer = false) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max || (integer && !Number.isSafeInteger(value))) throw fail('project_invalid_number');
  return value;
}
function choice(value, options, fallback = 'unknown') {
  const result = value ?? fallback;
  if (!options.includes(result)) throw fail('project_invalid_choice');
  return result;
}
function revision(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw fail('project_revision_required', 409);
  return value;
}
function payload(value) {
  object(value, ['roles','contact','nickname','device','availability','skills','intendedUse','notes','consent','consentVersion']);
  if (!Array.isArray(value.roles) || !value.roles.length || value.roles.length > ROLES.size || new Set(value.roles).size !== value.roles.length || value.roles.some(role => !ROLES.has(role))) throw fail('project_invalid_roles');
  const contact = object(value.contact, ['type','value']);
  const type = choice(contact.type, ['email','telegram','discord','x','other'], 'other');
  const contactValue = text(contact.value, 240, true);
  if (/[\r\n\t]/.test(contactValue) || (type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(contactValue))) throw fail('project_invalid_contact');
  if (value.consent !== true || value.consentVersion !== RECRUITMENT_CONSENT) throw fail('project_consent_required');
  const device = object(value.device ?? {}, ['cpuModel','threads','memoryGiB','operatingSystem','diskGiB','gpuModel','gpuMemoryGiB']);
  const availability = object(value.availability ?? {}, ['hoursPerDay','continuous','client']);
  return {
    roles: [...value.roles].sort(), contact: {type, value: contactValue}, nickname: text(value.nickname, 80),
    device: {cpuModel: text(device.cpuModel,160), threads: number(device.threads,1,4096,true), memoryGiB: number(device.memoryGiB,0,4096), operatingSystem: choice(device.operatingSystem,['linux','windows','macos','other','unknown']), diskGiB: number(device.diskGiB,0,1048576), gpuModel: text(device.gpuModel,160), gpuMemoryGiB: number(device.gpuMemoryGiB,0,4096)},
    availability: {hoursPerDay: number(availability.hoursPerDay,0,24), continuous: choice(availability.continuous,['yes','no','unknown']), client: choice(availability.client,['browser','local','either','unknown'])},
    skills: text(value.skills,1000), intendedUse: text(value.intendedUse,1000), notes: text(value.notes,2000), consent: true, consentVersion: RECRUITMENT_CONSENT
  };
}

export class ProjectRecruitmentService {
  constructor(community, {catalog = null} = {}) { this.community = community; this.db = community.db; this.clock = community.clock; this.catalog = catalog; }
  async initialize() {
    this.catalog ??= JSON.parse(await readFile(new URL('../config/research-projects-v1.json', import.meta.url), 'utf8'));
    if (this.catalog.schemaVersion !== 'fbw-research-projects-v1' || this.catalog.consentVersion !== RECRUITMENT_CONSENT || this.catalog.projects?.length !== 9) throw fail('project_catalog_invalid',503);
    this.projects = new Map();
    const slugs = new Set();
    for (const [index, project] of this.catalog.projects.entries()) {
      if (project.id !== `FBW-P${String(index + 1).padStart(2,'0')}` || !/^[a-z][a-z0-9-]+$/.test(project.slug) || slugs.has(project.slug) || !['open','waitlist','closed'].includes(project.recruitmentStatus)) throw fail('project_catalog_invalid',503);
      this.projects.set(project.id, project); slugs.add(project.slug);
    }
    const sql = await readFile(new URL('../config/social-community-v4.sql', import.meta.url),'utf8');
    this.community.transaction(() => {
      const applied = this.db.prepare('SELECT sha256 FROM social_schema_migrations WHERE version=4').get();
      if (applied && applied.sha256 !== hash(sql)) throw fail('migration_hash_conflict',503);
      if (!applied) { this.db.exec(sql); this.db.prepare('INSERT INTO social_schema_migrations VALUES(4,?,?,?)').run('social-community-v4-project-recruitment',hash(sql),this.clock()); }
    });
    return this;
  }
  project(id, open = false) {
    const project = this.projects.get(id);
    if (!project) throw fail('project_unknown');
    if (open && project.recruitmentStatus === 'closed') throw fail('project_recruitment_closed',409);
    return project;
  }
  execute(session, body, action, operation) {
    const requestId = text(body.requestId,80,true);
    if (!/^[A-Za-z0-9_-]{16,80}$/.test(requestId)) throw fail('project_invalid_request_id');
    const payloadHash = hash(canonical(Object.fromEntries(Object.entries(body).filter(([key]) => key !== 'requestId'))));
    return this.community.transaction(() => {
      const old = this.db.prepare('SELECT * FROM project_request_idempotency WHERE actor_wallet=? AND request_id=?').get(session.wallet,requestId);
      if (old) {
        if (old.action !== action || old.payload_hash !== payloadHash) throw fail('project_request_conflict',409);
        return JSON.parse(old.response_json);
      }
      if (this.db.prepare('SELECT COUNT(*) n FROM project_request_idempotency WHERE actor_wallet=? AND created_at>?').get(session.wallet,this.clock()-60).n >= 30) throw Object.assign(fail('project_rate_limited',429),{retryAfter:60});
      const result = operation();
      this.db.prepare('INSERT INTO project_request_idempotency VALUES(?,?,?,?,?,?)').run(session.wallet,requestId,action,payloadHash,JSON.stringify(result),this.clock());
      return result;
    });
  }
  view(row, admin = false) {
    return {id:row.id, projectId:row.project_id, ...JSON.parse(row.payload_json), status:row.status, revision:row.revision, publicNote:row.public_note, createdAt:row.created_at, updatedAt:row.updated_at, ...(admin ? {wallet:row.subject_wallet,internalNote:row.internal_note,primaryPreference:this.db.prepare('SELECT primary_project_id FROM project_preferences WHERE subject_wallet=?').get(row.subject_wallet)?.primary_project_id===row.project_id} : {})};
  }
  owned(session, id) {
    const row = this.db.prepare('SELECT * FROM project_applications WHERE id=? AND subject_wallet=?').get(id,session.wallet);
    if (!row) throw fail('project_application_not_found',404);
    return row;
  }
  event(row, actor, action, previous = null) {
    this.db.prepare('INSERT INTO project_application_events(application_id,actor_wallet,action,previous_status,status,revision,public_note,internal_note,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)').run(row.id,actor,action,previous,row.status,row.revision,row.public_note,row.internal_note,row.payload_json,this.clock());
  }
  setPreferenceInside(wallet, projectId, enabled) {
    if (enabled) this.db.prepare('INSERT INTO project_preferences VALUES(?,?,?) ON CONFLICT(subject_wallet) DO UPDATE SET primary_project_id=excluded.primary_project_id,updated_at=excluded.updated_at').run(wallet,projectId,this.clock());
    else this.db.prepare('DELETE FROM project_preferences WHERE subject_wallet=? AND primary_project_id=?').run(wallet,projectId);
  }
  interestInside(wallet, projectId, interested) {
    this.db.prepare('INSERT INTO project_interests VALUES(?,?,?,?,?) ON CONFLICT(subject_wallet,project_id) DO UPDATE SET interested=excluded.interested,updated_at=excluded.updated_at').run(wallet,projectId,Number(interested),this.clock(),this.clock());
  }
  me(session) {
    return {applications:this.db.prepare('SELECT * FROM project_applications WHERE subject_wallet=? ORDER BY created_at,id').all(session.wallet).map(row=>this.view(row)), interests:this.db.prepare('SELECT project_id FROM project_interests WHERE subject_wallet=? AND interested=1 ORDER BY project_id').all(session.wallet).map(row=>row.project_id), primaryProjectId:this.db.prepare('SELECT primary_project_id FROM project_preferences WHERE subject_wallet=?').get(session.wallet)?.primary_project_id??null, consentVersion:RECRUITMENT_CONSENT, asOf:this.clock()};
  }
  interest(session, body) {
    object(body,['requestId','projectId','interested']); this.project(body.projectId);
    if (typeof body.interested !== 'boolean') throw fail('project_invalid_choice');
    return this.execute(session,body,'interest',()=>{this.interestInside(session.wallet,body.projectId,body.interested);return {projectId:body.projectId,interested:body.interested,asOf:this.clock()};});
  }
  preference(session, body) {
    object(body,['requestId','projectId']); if(body.projectId!==null)this.project(body.projectId,true);
    return this.execute(session,body,'preference',()=>{if(body.projectId===null)this.db.prepare('DELETE FROM project_preferences WHERE subject_wallet=?').run(session.wallet);else this.setPreferenceInside(session.wallet,body.projectId,true);return {primaryProjectId:body.projectId,asOf:this.clock()};});
  }
  submit(session, body) {
    object(body,['requestId','projectId','application','primaryPreference']); const application=payload(body.application);
    if(body.primaryPreference!==undefined&&typeof body.primaryPreference!=='boolean')throw fail('project_invalid_choice');
    return this.execute(session,body,'submit',()=>{
      this.project(body.projectId,true);
      if(this.db.prepare('SELECT 1 FROM project_applications WHERE subject_wallet=? AND project_id=?').get(session.wallet,body.projectId))throw fail('project_application_exists',409);
      const id=randomBytes(16).toString('hex'),now=this.clock();
      this.db.prepare("INSERT INTO project_applications(id,subject_wallet,project_id,payload_json,consent_version,status,revision,created_at,updated_at) VALUES(?,?,?,?,?,'submitted',1,?,?)").run(id,session.wallet,body.projectId,canonical(application),RECRUITMENT_CONSENT,now,now);
      this.interestInside(session.wallet,body.projectId,true);
      if(body.primaryPreference!==undefined)this.setPreferenceInside(session.wallet,body.projectId,body.primaryPreference);
      const row=this.owned(session,id);this.event(row,session.wallet,'submit');return {application:this.view(row),receivedAt:now};
    });
  }
  change(session, id, action, body) {
    object(body,action==='withdraw'?['requestId','revision']:['requestId','revision','application','primaryPreference']);
    const expected=revision(body.revision),application=action==='withdraw'?null:payload(body.application);
    if(body.primaryPreference!==undefined&&typeof body.primaryPreference!=='boolean')throw fail('project_invalid_choice');
    return this.execute(session,body,action+':'+id,()=>{
      const old=this.owned(session,id);
      if(old.revision!==expected)throw fail('project_revision_conflict',409);
      if(action==='resubmit') {this.project(old.project_id,true);if(!['withdrawn','rejected'].includes(old.status))throw fail('project_invalid_transition',409);}
      else if(old.status==='withdrawn')throw fail('project_invalid_transition',409);
      const status=action==='withdraw'?'withdrawn':'submitted';
      this.db.prepare('UPDATE project_applications SET payload_json=?,status=?,revision=revision+1,updated_at=?,public_note=? WHERE id=? AND revision=?').run(application?canonical(application):old.payload_json,status,this.clock(),'',id,expected);
      if(action==='withdraw')this.setPreferenceInside(session.wallet,old.project_id,false);
      else {this.interestInside(session.wallet,old.project_id,true);if(body.primaryPreference!==undefined)this.setPreferenceInside(session.wallet,old.project_id,body.primaryPreference);}
      const row=this.owned(session,id);this.event(row,session.wallet,action,old.status);return {application:this.view(row),receivedAt:this.clock()};
    });
  }
  stats() {
    const count=(sql,...args)=>Number(this.db.prepare(sql).get(...args).n);
    return {catalogVersion:this.catalog.catalogVersion,projects:[...this.projects.values()].map(project=>({projectId:project.id,status:project.status,recruitmentStatus:project.recruitmentStatus,interestedAccounts:count('SELECT COUNT(*) n FROM project_interests WHERE project_id=? AND interested=1',project.id),applicationAccounts:count(`SELECT COUNT(*) n FROM project_applications WHERE project_id=? AND status IN ${ACTIVE}`,project.id),selectedAccounts:count("SELECT COUNT(*) n FROM project_applications WHERE project_id=? AND status='selected'",project.id),primaryPreferenceAccounts:count('SELECT COUNT(*) n FROM project_preferences WHERE primary_project_id=?',project.id)})),totalUniqueApplicants:count(`SELECT COUNT(DISTINCT subject_wallet) n FROM project_applications WHERE status IN ${ACTIVE}`),applicationStatusBasis:['submitted','reviewing','waitlisted','selected'],identityBasis:'authenticated wallet accounts; not verified distinct people',asOf:this.clock()};
  }
  filters(query={}) {
    const {projectId='',role='',status='',offset='0',limit='25'}=query;
    if(projectId)this.project(projectId);if(role&&!ROLES.has(role))throw fail('project_invalid_roles');if(status&&!STATUSES.has(status))throw fail('project_invalid_status');
    if(!/^\d{1,7}$/.test(String(offset))||Number(offset)>1000000||!/^\d{1,3}$/.test(String(limit))||Number(limit)<1||Number(limit)>100)throw fail('project_invalid_cursor');
    const where=[],args=[];
    if(projectId){where.push('project_id=?');args.push(projectId);}
    if(status){where.push('status=?');args.push(status);}
    if(role){where.push("EXISTS(SELECT 1 FROM json_each(payload_json,'$.roles') WHERE value=?)");args.push(role);}
    return {where:where.length?' WHERE '+where.join(' AND '):'',args,offset:Number(offset),limit:Number(limit)};
  }
  adminList(session, query) {
    this.community.admin(session);const f=this.filters(query);
    return {items:this.db.prepare('SELECT * FROM project_applications'+f.where+' ORDER BY updated_at DESC,id LIMIT ? OFFSET ?').all(...f.args,f.limit,f.offset).map(row=>this.view(row,true)),total:Number(this.db.prepare('SELECT COUNT(*) n FROM project_applications'+f.where).get(...f.args).n),offset:f.offset,limit:f.limit,asOf:this.clock()};
  }
  adminSummary(session) {
    this.community.admin(session);
    return {...this.stats(),totalApplicationRecords:Number(this.db.prepare('SELECT COUNT(*) n FROM project_applications').get().n),allTimeUniqueApplicants:Number(this.db.prepare('SELECT COUNT(DISTINCT subject_wallet) n FROM project_applications').get().n),byStatus:this.db.prepare('SELECT status,COUNT(*) records FROM project_applications GROUP BY status').all(),byRole:[...ROLES].map(role=>({role,records:Number(this.db.prepare("SELECT COUNT(*) n FROM project_applications WHERE EXISTS(SELECT 1 FROM json_each(payload_json,'$.roles') WHERE value=?)").get(role).n)}))};
  }
  adminDetail(session,id,{before='0'}={}) {
    this.community.admin(session);
    if(!/^\d{1,16}$/.test(String(before))||!Number.isSafeInteger(Number(before)))throw fail('project_invalid_cursor');
    const row=this.db.prepare('SELECT * FROM project_applications WHERE id=?').get(id);if(!row)throw fail('project_application_not_found',404);
    const rows=this.db.prepare('SELECT * FROM project_application_events WHERE application_id=? AND (?=0 OR sequence<?) ORDER BY sequence DESC LIMIT 101').all(id,Number(before),Number(before));
    return {application:this.view(row,true),events:rows.slice(0,100).map(event=>({sequence:event.sequence,actor:event.actor_wallet,action:event.action,previousStatus:event.previous_status,status:event.status,revision:event.revision,publicNote:event.public_note,internalNote:event.internal_note,application:JSON.parse(event.payload_json),createdAt:event.created_at})),nextBefore:rows.length>100?rows[99].sequence:null};
  }
  review(session,id,body) {
    this.community.admin(session,{recent:true});object(body,['requestId','revision','status','internalNote','publicNote']);const expected=revision(body.revision);
    if(!STATUSES.has(body.status)||body.status==='withdrawn')throw fail('project_invalid_status');
    const internal=text(body.internalNote,2000)??'',publicNote=text(body.publicNote,1000)??'';
    return this.execute(session,body,'review:'+id,()=>{
      const old=this.db.prepare('SELECT * FROM project_applications WHERE id=?').get(id);if(!old)throw fail('project_application_not_found',404);
      if(old.revision!==expected)throw fail('project_revision_conflict',409);if(old.status==='withdrawn')throw fail('project_invalid_transition',409);
      this.db.prepare('UPDATE project_applications SET status=?,internal_note=?,public_note=?,revision=revision+1,updated_at=? WHERE id=? AND revision=?').run(body.status,internal,publicNote,this.clock(),id,expected);
      const row=this.db.prepare('SELECT * FROM project_applications WHERE id=?').get(id);this.event(row,session.wallet,'review',old.status);return {application:this.view(row,true),receivedAt:this.clock()};
    });
  }
  exportCsv(session,query) {
    this.community.admin(session);const f=this.filters(query),rows=this.db.prepare('SELECT * FROM project_applications'+f.where+' ORDER BY updated_at DESC,id LIMIT 10001').all(...f.args);
    if(rows.length>10000)throw fail('project_export_limit',409);
    const columns=['id','wallet','projectId','roles','primaryPreference','status','revision','createdAt','updatedAt','nickname','contactType','contactValue','cpuModel','threads','memoryGiB','operatingSystem','diskGiB','gpuModel','gpuMemoryGiB','hoursPerDay','continuous','client','skills','intendedUse','notes','publicNote','internalNote'];
    const cell=value=>{let text=String(value??'');if(/^[\s\x00-\x1f]*[=+\-@]/.test(text)||/^[\t\r]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';};
    return '\uFEFF'+columns.map(cell).join(',')+'\r\n'+rows.map(row=>{const p=this.view(row,true);const flat={...p,...p.device,...p.availability,roles:p.roles.join(';'),contactType:p.contact.type,contactValue:p.contact.value};return columns.map(key=>cell(flat[key])).join(',');}).join('\r\n')+'\r\n';
  }
}
