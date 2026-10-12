//! TargetRoundAuthority V2: one durable development authority, not consensus.
//! No legacy write flag, payment, Solana V1 account, or token code is used here.
use axum::{body::Bytes,extract::{State,Path,Query,DefaultBodyLimit},http::{HeaderMap,StatusCode,Method},response::{IntoResponse,Response,sse::{Sse,Event,KeepAlive}},routing::{get,post,put},Json,Router};
use ed25519_dalek::{Signature,Signer,SigningKey,VerifyingKey};
use flypow_target_protocol::{self as p,GoalSpec,CandidateManifest,Result,difficulty::{Controller,Level},canonical,hash,id,root,value};
use rusqlite::{Connection,OptionalExtension,TransactionBehavior,params};
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::{fs,io::Write,path::PathBuf,sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}},time::{SystemTime,UNIX_EPOCH}};
#[path="target_lifecycle.rs"]
mod lifecycle;
#[path="target_metrics.rs"]
mod metrics;
#[path="private_delivery.rs"]
mod private_delivery;
#[path="product_objects.rs"]
mod product_objects;
#[path="product.rs"]
pub mod product;
#[path="business_accounting.rs"]
mod business_accounting;
#[path="market/mod.rs"]
pub mod market;
#[path="chain_reconciliation.rs"]
mod chain_reconciliation;
#[path="economic_ledger.rs"]
pub mod economic_ledger;
pub const CHUNK:usize=4*1024*1024;
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct AuthorityConfig {
    pub schema:String,pub network_id:String,pub campaign_id:String,pub goal_paths:Vec<PathBuf>,
    pub verifier_keys:Vec<String>,pub admin_keys:Vec<String>,pub allowed_origins:Vec<String>,
    pub tau_seconds:u64,pub search_seconds:u64,pub reveal_seconds:u64,pub verification_seconds:u64,
    pub max_queue:u32,pub per_identity_claims:u32,pub max_private_bytes:u64,
    #[serde(default)]pub family_paths:Vec<PathBuf>,
}
impl AuthorityConfig {
    pub fn validate(&self)->Result<()>{
        if self.schema!="flypow-target-authority-config-v2"||self.network_id.is_empty()||self.network_id.len()>128||self.campaign_id.is_empty()||self.goal_paths.is_empty()||self.goal_paths.len()>128||self.verifier_keys.len()!=3||self.admin_keys.is_empty()||self.tau_seconds==0||self.tau_seconds>86400||self.search_seconds<60||self.search_seconds>86400||self.reveal_seconds<60||self.reveal_seconds>86400||self.verification_seconds<60||self.verification_seconds>86400||self.search_seconds+self.reveal_seconds+self.verification_seconds>86400||self.max_queue==0||self.max_queue>64||self.per_identity_claims==0||self.per_identity_claims>4||self.max_private_bytes>8*1024*1024*1024{return Err("configuration bounds".into());}
        let mut unique=std::collections::BTreeSet::new();for k in &self.verifier_keys{root(k)?;if !unique.insert(k){return Err("three distinct verifier keys required".into());}}for k in &self.admin_keys{root(k)?;}Ok(())
    }
    pub fn policy(&self)->Value{json!({"schema":"flypow-difficulty-policy-v2","tauSeconds":self.tau_seconds,"searchSeconds":self.search_seconds,"revealSeconds":self.reveal_seconds,"verificationSeconds":self.verification_seconds,"controller":"ewma-fixed-point-bounded-v2","minSamples":16,"quorum":2,"verifierKeys":self.verifier_keys,"maxQueue":self.max_queue,"perIdentityClaims":self.per_identity_claims,"scheduling":{"version":"retry-cooldown-v1","cooldownSeconds":60,"maxConsecutiveAttempts":2},"admission":{"version":"bounded-resources-v1","maxIncompleteUploads":64,"maxConcurrentLeases":3,"maxPendingPerSource":2,"proof":"bounded-queue-not-sybil-resistance"}})}
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct SignedRequest {pub public_key:String,pub action:String,pub request_id:String,pub round_id:String,pub payload:Value,pub signature:String}
impl SignedRequest {
    pub fn unsigned(&self)->Value{json!({"publicKey":self.public_key,"action":self.action,"requestId":self.request_id,"roundId":self.round_id,"payload":self.payload})}
    pub fn authenticate(&self,action:&str)->Result<()> {
        root(&self.public_key)?;if self.action!=action||self.request_id.len()<8||self.request_id.len()>128||!self.request_id.bytes().all(|c|c.is_ascii_alphanumeric()||b"-_".contains(&c)){return Err("BAD_SIGNATURE: action/request identity".into());}
        let k: [u8;32]=p::unhex(&self.public_key)?.try_into().map_err(|_|"key width")?;let s: [u8;64]=p::unhex(&self.signature)?.try_into().map_err(|_|"signature width")?;
        VerifyingKey::from_bytes(&k).map_err(|_|"BAD_SIGNATURE: key")?.verify_strict(&p::unhex(&id("authority-action",&self.unsigned())?)?,&Signature::from_bytes(&s)).map_err(|_|"BAD_SIGNATURE: signed action".to_string())
    }
}
pub struct Authority {pub data:PathBuf,pub config:AuthorityConfig,pub authority_id:String,key:SigningKey,db:Mutex<Connection>,wall_clock:AtomicBool,pub(crate) event_bus:tokio::sync::broadcast::Sender<Value>}
pub fn now()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()}
fn sync_dir(path:&std::path::Path)->Result<()>{fs::File::open(path).and_then(|f|f.sync_all()).map_err(|e|format!("storage: directory durability: {e}"))}
fn random_suffix()->Result<String>{let mut b=[0u8;8];getrandom::fill(&mut b).map_err(|e|e.to_string())?;Ok(p::hex(&b))}
fn parse(s:String)->Result<Value>{serde_json::from_str(&s).map_err(|e|e.to_string())}
fn text(v:&Value,k:&str)->Result<String>{v[k].as_str().map(String::from).ok_or(format!("INVALID_INPUT: {k}"))}
fn num(v:&Value,k:&str)->Result<u64>{v[k].as_u64().ok_or(format!("INVALID_INPUT: {k}"))}
fn sql<T>(r:rusqlite::Result<T>)->Result<T>{r.map_err(|e|format!("storage: {e}"))}
impl Authority {
    pub fn open(data:PathBuf,config:AuthorityConfig)->Result<Arc<Self>>{
        config.validate()?;fs::create_dir_all(&data).map_err(|e|e.to_string())?;
        let private=data.join("private");fs::create_dir_all(&private).map_err(|e|e.to_string())?;
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;fs::set_permissions(&private,fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())?;}
        let key_path=private.join("authority-v2.key");let secret=if key_path.exists(){fs::read(&key_path).map_err(|e|e.to_string())?}else{let mut b=[0u8;32];getrandom::fill(&mut b).map_err(|e|e.to_string())?;let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&key_path).map_err(|e|e.to_string())?;
            #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;f.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;}f.write_all(&b).map_err(|e|e.to_string())?;f.sync_all().map_err(|e|e.to_string())?;b.to_vec()};
        let key=SigningKey::from_bytes(&secret.try_into().map_err(|_|"authority key length")?);let authority_id=p::hex(key.verifying_key().as_bytes());
        let db=sql(Connection::open(data.join("target-v2.sqlite")))?;sql(db.busy_timeout(std::time::Duration::from_secs(10)))?;sql(db.execute_batch(include_str!("../config/target-mining-v2.sql")))?;
        let a=Arc::new(Self{data,config,authority_id,key,db:Mutex::new(db),wall_clock:AtomicBool::new(false),event_bus:tokio::sync::broadcast::channel(256).0});a.initialize()?;a.product_initialize()?;a.market_initialize()?;a.archive_housekeeping(now())?;Ok(a)
    }
    fn lock(&self)->Result<std::sync::MutexGuard<'_,Connection>>{self.db.lock().map_err(|_|"authority DB unavailable".into())}
    pub fn sign(&self,domain:&str,v:&Value)->Result<String>{Ok(p::hex(&self.key.sign(&p::unhex(&id(domain,v)?)?).to_bytes()))}
    fn signed(&self,domain:&str,mut v:Value)->Result<Value>{let sig=self.sign(domain,&v)?;v.as_object_mut().ok_or("signed object")?.insert("signature".into(),json!(sig));Ok(v)}
    fn initialize(&self)->Result<()> {
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let saved:Option<String>=sql(tx.query_row("SELECT config_json FROM target_campaigns WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)).optional())?;
        if let Some(s)=saved {let old:AuthorityConfig=serde_json::from_value(parse(s)?).map_err(|e|e.to_string())?;if value(&old)!=value(&self.config){return Err("Existing campaign configuration differs; publish a future policy or use a new campaign".into());}return Ok(());}
        let mut scientific_tasks=Self::registered_scientific_tasks(&tx)?;
        sql(tx.execute("INSERT INTO target_campaigns VALUES(?,?,'CALIBRATION_REQUIRED')",params![self.config.campaign_id,serde_json::to_string(&self.config).unwrap()]))?;
        for (index,path) in self.config.goal_paths.iter().enumerate(){
            let goal:GoalSpec=serde_json::from_slice(&fs::read(path).map_err(|e|format!("goal {path:?}: {e}"))?).map_err(|e|e.to_string())?;goal.validate()?;
            let cp=path.with_file_name("calibration.json");let calibration:Value=serde_json::from_slice(&fs::read(cp).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            if hash(&canonical(&calibration)?)!=goal.calibration_hash||calibration["schema"]!="flypow-target-calibration-v2"||calibration["scientificDefinitionHash"]!= {let mut definition=value(&goal);definition.as_object_mut().unwrap().remove("calibrationHash");id("calibration-science",&definition)?}||goal.neuron_count!=165122||goal.graph_root!="6c42f6ff8e2198aca17a765acae0475b490abb0169d615e32b71c976f563deb4"{return Err("Full MaleCNS calibration identity required; fixtures cannot activate this authority".into());}
            if !scientific_tasks.insert(crate::product_identity::task(&goal)?){return Err("CONFLICT: scientific task already registered; renaming or changing campaign does not create discovery supply".into());}
            let gid=goal.goal_id()?;sql(tx.execute("INSERT OR IGNORE INTO goal_specs VALUES(?,?,?)",params![gid,serde_json::to_string(&goal).unwrap(),calibration.to_string()]))?;
            sql(tx.execute("INSERT INTO goal_plan_progress(campaign_id,plan_index,goal_id) VALUES(?,?,?)",params![self.config.campaign_id,index,gid]))?;
        }
        for path in &self.config.family_paths {let f:p::family::Family=serde_json::from_slice(&fs::read(path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;Self::register_family(&tx,&f)?;}
        let policy=id("difficulty-policy",&self.config.policy())?;
        sql(tx.execute("INSERT INTO target_audit(action,payload_json,at) VALUES('CAMPAIGN_CONFIGURED',?,?)",params![self.config.policy().to_string(),now()]))?;
        sql(tx.execute("INSERT INTO difficulty_snapshots VALUES(?, '{}',?,1)",params![self.config.campaign_id,policy]))?;sql(tx.commit())?;Ok(())
    }
    fn round(db:&Connection,rid:&str)->Result<Value>{let s:String=sql(db.query_row("SELECT descriptor_json FROM target_rounds WHERE round_id=?",[rid],|r|r.get(0)))?;parse(s)}
    fn registered_scientific_tasks(db:&Connection)->Result<std::collections::BTreeSet<String>> {
        // Read existing definitions, including historical aliases, without
        // rewriting frozen GoalIds or changing their original eligibility.
        let mut statement=sql(db.prepare("SELECT spec_json FROM goal_specs"))?;
        let rows=sql(statement.query_map([],|r|r.get::<_,String>(0)))?;
        let mut tasks=std::collections::BTreeSet::new();
        for row in rows {
            let goal:GoalSpec=serde_json::from_str(&sql(row)?).map_err(|e|format!("storage: registered goal: {e}"))?;
            tasks.insert(crate::product_identity::task(&goal)?);
        }
        Ok(tasks)
    }
    fn event(&self,db:&Connection,rid:Option<&str>,kind:&str,payload:Value,at:u64)->Result<()> {
        sql(db.execute("INSERT INTO protocol_events(round_id,kind,payload_json,created_at) VALUES(?,?,'{}',?)",params![rid,kind,at]))?;let seq=db.last_insert_rowid();
        let signed=self.signed("protocol-event",json!({"eventSequence":seq,"networkId":self.config.network_id,"authorityId":self.authority_id,"roundId":rid,"kind":kind,"payload":payload,"createdAt":at}))?;
        sql(db.execute("UPDATE protocol_events SET payload_json=? WHERE event_sequence=?",params![signed.to_string(),seq]))?;sql(db.execute("INSERT INTO protocol_outbox(event_sequence) VALUES(?)",[seq]))?;Ok(())
    }
    fn levels(cal:&Value)->Result<Vec<Level>> {
        let mut out=Vec::new();if cal["activationAllowed"]!=true{return Ok(out);}
        for l in cal["levels"].as_array().ok_or("calibration levels")? {if l["enabled"]==true {
            if num(l,"heldOutSuccesses")?==0||num(l,"sampleCount")?<16||l["challengeEffective"]!=true||num(l,"passRatePartsPerMillion")?==0||num(l,"passRatePartsPerMillion")?>=900000{return Err("calibration activation gate".into());}
            out.push(Level{profile_id:text(l,"profileId")?,required_backgrounds:num(l,"requiredBackgrounds")? as u32,difficulty_micros:num(l,"difficultyMicros")?,calibration_hash:hash(&canonical(cal)?),enabled:true});
        }}if !out.is_empty(){Controller::validate_levels(&out)?;}Ok(out)
    }
    fn register_family(db:&Connection,f:&p::family::Family)->Result<()> {
        let mut evidence=Vec::new();for member in &f.members {let (g,c):(String,String)=sql(db.query_row("SELECT spec_json,calibration_json FROM goal_specs WHERE goal_id=?",[&member.goal_id],|r|Ok((r.get(0)?,r.get(1)?))))?;evidence.push((serde_json::from_str(&g).map_err(|e|e.to_string())?,parse(c)?));}
        f.validate_evidence(&evidence)?;let fid=f.identity()?;sql(db.execute("INSERT OR IGNORE INTO comparable_difficulty_families VALUES(?,?)",params![fid,serde_json::to_string(f).unwrap()]))?;
        for m in &f.members {let previous:Option<String>=sql(db.query_row("SELECT family_id FROM goal_difficulty_families WHERE goal_id=?",[&m.goal_id],|r|r.get(0)).optional())?;if previous.as_ref().is_some_and(|p|p!=&fid){return Err("CONFLICT: existing goal family immutable; new calibration cold-starts".into());}sql(db.execute("INSERT OR IGNORE INTO goal_difficulty_families VALUES(?,?)",params![m.goal_id,fid]))?;}Ok(())
    }
    fn family_for(db:&Connection,g:&Value,cal:&Value)->Result<(String,Vec<Level>,Option<Value>)> {
        let goal:GoalSpec=serde_json::from_value(g.clone()).map_err(|e|e.to_string())?;let gid=goal.goal_id()?;
        let descriptor:Option<String>=sql(db.query_row("SELECT descriptor_json FROM comparable_difficulty_families JOIN goal_difficulty_families USING(family_id) WHERE goal_id=?",[&gid],|r|r.get(0)).optional())?;
        if let Some(s)=descriptor {let f:p::family::Family=serde_json::from_str(&s).map_err(|e|e.to_string())?;let m=f.member(&goal)?;let fid=f.identity()?;return Ok((fid.clone(),f.controller_levels()?,Some(json!({"familyId":fid,"descriptor":f,"normalizationNumerator":m.normalization_numerator,"normalizationDenominator":m.normalization_denominator}))));}
        Ok((id("calibration-family",&json!({"family":g["family"],"graphRoot":g["graphRoot"],"parameterProfileHash":g["parameterProfileHash"],"calibrationHash":g["calibrationHash"]}))?,Self::levels(cal)?,None))
    }
    fn capabilities(&self,db:&Connection,round:Option<&Value>)->Result<Value> {
        // A completed finite plan still has measured capabilities and persisted
        // feedback. Report the last frozen round as historical context, never
        // as an open round and without creating another competition.
        let historical:Option<Value>=if round.is_none(){sql(db.query_row("SELECT descriptor_json FROM target_rounds WHERE campaign_id=? ORDER BY sequence DESC LIMIT 1",[&self.config.campaign_id],|r|r.get::<_,String>(0)).optional())?.map(parse).transpose()?}else{None};
        let Some(r)=round.or(historical.as_ref()) else{return Ok(json!({"levels":[],"controller":null,"source":"no-current-round","minComparableSuccessfulRounds":16}));};
        let cal=parse(sql(db.query_row("SELECT calibration_json FROM goal_specs WHERE goal_id=?",[text(&r["pre"],"goalId")?],|x|x.get(0)))?)?;let (family,levels,_)=Self::family_for(db,&r["goal"],&cal)?;
        let controller:Option<String>=sql(db.query_row("SELECT controller_json FROM difficulty_family_controllers WHERE campaign_id=? AND family_id=?",params![self.config.campaign_id,family],|x|x.get(0)).optional())?;
        Ok(json!({"familyId":family,"levels":levels,"controller":controller.map(parse).transpose()?,"minComparableSuccessfulRounds":16,"currentRoundAvailable":round.is_some(),"basisRoundId":r["roundId"],"source":if round.is_some(){"validated calibration and immutable frozen family policy"}else{"last frozen round; historical capabilities only, no open round"}}))
    }
    // HTTP runtime samples the server clock after I/O and inside its locked
    // transaction. Pure state tests retain their explicitly injected clock.
    pub fn use_wall_clock(&self){self.wall_clock.store(true,Ordering::SeqCst);}
    fn check_clock(&self,db:&Connection,at:u64)->Result<u64> {let at=if self.wall_clock.load(Ordering::SeqCst){now()}else{at};let prior:u64=sql(db.query_row("SELECT last_at FROM target_clock WHERE singleton=1",[],|x|x.get(0)))?;if at<prior{return Err("CLOCK_ROLLBACK: persisted authority time".into());}sql(db.execute("UPDATE target_clock SET last_at=? WHERE singleton=1",[at]))?;Ok(at)}
    pub fn maintain(&self,at:u64)->Result<()> {
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;
        self.expire_history_tx(&tx,at)?;
        let active:Option<String>=sql(tx.query_row("SELECT round_id FROM target_rounds WHERE campaign_id=? AND status IN ('OPEN','VERIFYING')",[&self.config.campaign_id],|r|r.get(0)).optional())?;
        if let Some(rid)=active {
            let verification_backlog:u64=sql(tx.query_row("SELECT COUNT(*) FROM candidate_claims WHERE round_id=? AND status='REVEALED'",[&rid],|x|x.get(0)))?;

            self.finalize_tx(&tx,&rid,at)?;
            let (status,claim,verify):(String,u64,u64)=sql(tx.query_row("SELECT status,claim_deadline,verification_deadline FROM target_rounds WHERE round_id=?",[&rid],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))))?;
            if status=="OPEN"&&at>claim{sql(tx.execute("UPDATE target_rounds SET status='VERIFYING',version=version+1 WHERE round_id=?",[&rid]))?;self.event(&tx,Some(&rid),"CLAIMS_CLOSED",json!({"newClaimsAllowed":false}),at)?;}
            let admitted:u64=sql(tx.query_row("SELECT COUNT(*) FROM candidate_claims WHERE round_id=? AND status IN ('COMMITTED','REVEALED','VALID')",[&rid],|x|x.get(0)))?;
            // Once new claims close and every admitted claim is terminal, there
            // is no remaining reveal/replay eligibility to wait for.
            if status!="FINALIZED"&&(at>verify||(at>claim&&admitted==0)) {
                sql(tx.execute("UPDATE target_rounds SET status='EXPIRED_NO_VALID_RESULT',version=version+1 WHERE round_id=?",[&rid]))?;
                let round=Self::round(&tx,&rid)?;let search=num(&round["pre"]["difficultyPolicy"],"searchSeconds")?;
                let healthy:i64=sql(tx.query_row("SELECT COUNT(*) FROM target_sessions WHERE round_id=? AND last_seen>? AND phase IN ('searching','computing')",params![rid,at.saturating_sub(search)],|r|r.get(0)))?;
                self.observe_tx(&tx,&rid,None,healthy>0&&verification_backlog==0,at)?;
                if round["pre"]["difficultyPolicy"]["scheduling"]["version"]=="retry-cooldown-v1" {
                    let gid=text(&round["pre"],"goalId")?;
                    sql(tx.execute("INSERT INTO goal_schedule VALUES(?,?,1,?,'no-valid-result','retry-cooldown-v1') ON CONFLICT(campaign_id,goal_id) DO UPDATE SET attempts=attempts+1,eligible_at=excluded.eligible_at,last_reason=excluded.last_reason",params![self.config.campaign_id,gid,at+60]))?;
                    let attempts:u64=sql(tx.query_row("SELECT attempts FROM goal_schedule WHERE campaign_id=? AND goal_id=?",params![self.config.campaign_id,gid],|r|r.get(0)))?;
                    if attempts>=2 {sql(tx.execute("UPDATE goal_schedule SET eligible_at=? WHERE campaign_id=? AND goal_id=?",params![at+3600,self.config.campaign_id,gid]))?;}
                    self.event(&tx,Some(&rid),"GOAL_DEFERRED",json!({"goalId":gid,"reason":"no-valid-result","attempts":attempts,"solved":false,"policy":"retry-cooldown-v1"}),at)?;
                }
                self.event(&tx,Some(&rid),"ROUND_EXPIRED",json!({"status":"EXPIRED_NO_VALID_RESULT","health":if verification_backlog>0{"verification-backlog-excluded"}else if healthy>0{"healthy-search-censored"}else{"client-offline-or-infrastructure-unknown"}}),at)?;
            }
        }
        let still:i64=sql(tx.query_row("SELECT COUNT(*) FROM target_rounds WHERE campaign_id=? AND status IN ('OPEN','VERIFYING')",[&self.config.campaign_id],|r|r.get(0)))?;
        if still==0{self.open_next_tx(&tx,at)?;}sql(tx.commit())?;Ok(())
    }
    fn open_next_tx(&self,tx:&Connection,at:u64)->Result<()> {
        let next:Option<String>=sql(tx.query_row("SELECT p.goal_id FROM goal_plan_progress p LEFT JOIN goal_schedule s USING(campaign_id,goal_id) WHERE p.campaign_id=? AND p.state='PENDING' AND COALESCE(s.eligible_at,0)<=? ORDER BY COALESCE(s.attempts,0),p.plan_index LIMIT 1",params![self.config.campaign_id,at],|r|r.get(0)).optional())?;
        let Some(gid)=next else{let pending:u64=sql(tx.query_row("SELECT COUNT(*) FROM goal_plan_progress WHERE campaign_id=? AND state='PENDING'",[&self.config.campaign_id],|r|r.get(0)))?;sql(tx.execute("UPDATE target_campaigns SET state=? WHERE campaign_id=?",params![if pending==0{"RESEARCH_STAGE_COMPLETE"}else{"SUPPLY_DEFERRED"},self.config.campaign_id]))?;return Ok(());};
        let (gs,cs):(String,String)=sql(tx.query_row("SELECT spec_json,calibration_json FROM goal_specs WHERE goal_id=?",[&gid],|r|Ok((r.get(0)?,r.get(1)?))))?;
        let g=parse(gs)?;let cal=parse(cs)?;let levels=Self::levels(&cal)?;
        if levels.is_empty(){sql(tx.execute("UPDATE target_campaigns SET state='CALIBRATION_REQUIRED' WHERE campaign_id=?",[&self.config.campaign_id]))?;return Ok(());}
        let (family,levels,extension)=Self::family_for(tx,&g,&cal)?;
        let stored:Option<String>=sql(tx.query_row("SELECT controller_json FROM difficulty_family_controllers WHERE campaign_id=? AND family_id=?",params![self.config.campaign_id,family],|r|r.get(0)).optional())?;
        // Import matching legacy state once. Never overwrite another family's state.
        let legacy:String=sql(tx.query_row("SELECT controller_json FROM difficulty_snapshots WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)))?;
        let c=stored.as_deref().and_then(|s|serde_json::from_str::<Controller>(s).ok()).or_else(||serde_json::from_str::<Controller>(&legacy).ok().filter(|c|c.family_key==family)).filter(|c|c.applied_index<levels.len()).unwrap_or(Controller::new(family,&levels,self.config.tau_seconds*1000)?);
        let future:Option<String>=sql(tx.query_row("SELECT policy_json FROM target_future_policies WHERE campaign_id=? ORDER BY revision DESC LIMIT 1",[&self.config.campaign_id],|x|x.get(0)).optional())?;
        let mut policy=future.map(parse).transpose()?.unwrap_or(self.config.policy());if let Some(extension)=extension{policy["comparableFamily"]=extension;}let policy_hash=id("difficulty-policy",&policy)?;
        let search=num(&policy,"searchSeconds")?;let reveal=num(&policy,"revealSeconds")?;let verification=num(&policy,"verificationSeconds")?;
        let mut c=c;c.tau_ms=num(&policy,"tauSeconds")?*1000;
        sql(tx.execute("UPDATE difficulty_snapshots SET controller_json=?,policy_hash=? WHERE campaign_id=?",params![serde_json::to_string(&c).unwrap(),policy_hash,self.config.campaign_id]))?;
        sql(tx.execute("INSERT INTO difficulty_family_controllers(campaign_id,family_id,controller_json) VALUES(?,?,?) ON CONFLICT(campaign_id,family_id) DO UPDATE SET controller_json=excluded.controller_json",params![self.config.campaign_id,c.family_key,serde_json::to_string(&c).unwrap()]))?;
        let level=&levels[c.applied_index];let (sequence,previous):(u64,String)=sql(tx.query_row("SELECT COALESCE(MAX(sequence),0),COALESCE((SELECT round_id FROM target_rounds WHERE campaign_id=? ORDER BY sequence DESC LIMIT 1),'') FROM target_rounds WHERE campaign_id=?",params![self.config.campaign_id,self.config.campaign_id],|r|Ok((r.get::<_,u64>(0)?+1,r.get(1)?))))?;
        let pre=json!({"protocolVersion":2,"networkId":self.config.network_id,"authorityId":self.authority_id,"campaignId":self.config.campaign_id,"roundSequence":sequence,"previousRoundDigest":previous,"goalId":gid,"goalDefinitionHash":gid,"graphRoot":g["graphRoot"],"modelRoot":g["modelRoot"],"parameterProfileHash":g["parameterProfileHash"],"evaluatorVersion":g["evaluatorVersion"],"inputDomainHash":g["inputDomainHash"],"calibrationHash":g["calibrationHash"],"difficultyPolicyHash":policy_hash,"difficultyPolicy":policy,"appliedProfile":level.profile_id,"requiredBackgrounds":level.required_backgrounds,"difficultyMicros":level.difficulty_micros,"openedAt":at,"claimDeadline":at+search,"revealDeadline":at+search+reveal,"verificationDeadline":at+search+reveal+verification,"verificationPolicy":{"version":"authorized-two-of-three-full-replay-v2","verifiers":self.config.verifier_keys,"quorum":2,"leaseSeconds":300,"maxCandidateBytes":g["maxCandidateBytes"]}});
        let ph=id("pre-round",&pre)?;let mut entropy=[0u8;32];getrandom::fill(&mut entropy).map_err(|e|e.to_string())?;let entropy=p::hex(&entropy);let seeds:Vec<_>=(0..levels.last().unwrap().required_backgrounds).map(|j|p::derive_seed(&ph,&entropy,j)).collect::<Result<_>>()?;
        let core=json!({"preRoundSpecHash":ph,"roundEntropy":entropy,"entropySource":"authority-csprng-dev-v1","seedDerivationVersion":"sha256-pre-entropy-u32le-u64le-v1","seeds":seeds});let rid=id("round-id",&core)?;
        let mut round=core;round["pre"]=pre;round["roundId"]=json!(rid);round["signedRevision"]=json!(1);round["goal"]=g;p::validate_round(&round)?;round=self.signed("round-descriptor",round)?;
        sql(tx.execute("INSERT INTO target_rounds(round_id,campaign_id,sequence,goal_id,descriptor_json,status,opened_at,claim_deadline,reveal_deadline,verification_deadline) VALUES(?,?,?,?,?,'OPEN',?,?,?,?)",params![rid,self.config.campaign_id,sequence,gid,round.to_string(),at,at+search,at+search+reveal,at+search+reveal+verification]))?;
        sql(tx.execute("UPDATE target_campaigns SET state='RUNNING_DEV_NO_PAYMENT' WHERE campaign_id=?",[&self.config.campaign_id]))?;self.event(tx,Some(&rid),"ROUND_OPENED",round,at)
    }
    pub fn current(&self)->Result<Value>{let db=self.lock()?;let state:String=sql(db.query_row("SELECT state FROM target_campaigns WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)))?;
        let active:Option<String>=sql(db.query_row("SELECT descriptor_json FROM target_rounds WHERE campaign_id=? AND status IN ('OPEN','VERIFYING')",[&self.config.campaign_id],|r|r.get(0)).optional())?;
        let seq:u64=sql(db.query_row("SELECT COALESCE(MAX(event_sequence),0) FROM protocol_events",[],|r|r.get(0)))?;
        let mut snapshot=json!({"networkId":self.config.network_id,"authorityId":self.authority_id,"campaignId":self.config.campaign_id,"state":state,"round":active.clone().map(parse).transpose()?,"eventSequence":seq,"serverTime":now(),"trust":"Single development authority; three local keys do not establish independent operation","payment":false,"rewards":false,"capabilities":self.capabilities(&db,active.as_ref().map(|s|parse(s.clone())).transpose()?.as_ref())?,"supply":self.supply(&db)?});snapshot.as_object_mut().unwrap().extend(self.product_identity(&db)?.as_object().unwrap().clone());self.signed("authority-snapshot",snapshot)
    }
    pub fn round_state(&self,rid:&str)->Result<Value>{root(rid)?;let db=self.lock()?;let r=Self::round(&db,rid)?;let status:String=sql(db.query_row("SELECT status FROM target_rounds WHERE round_id=?",[rid],|r|r.get(0)))?;let w:Option<String>=sql(db.query_row("SELECT winner_json FROM round_winners WHERE round_id=?",[rid],|r|r.get(0)).optional())?;self.signed("round-state",json!({"round":r,"status":status,"winner":w.map(parse).transpose()?,"serverTime":now()}))}
    fn cached(db:&Connection,r:&SignedRequest)->Result<Option<Value>>{let old:Option<(String,String)>=sql(db.query_row("SELECT request_hash,response_json FROM request_receipts WHERE miner_id=? AND request_id=?",params![r.public_key,r.request_id],|x|Ok((x.get(0)?,x.get(1)?))).optional())?;
        if let Some((h,v))=old {if h!=id("request",&r.unsigned())?{return Err("CONFLICT: idempotency key reused with different request".into());}return Ok(Some(parse(v)?));}Ok(None)
    }
    fn remember(db:&Connection,r:&SignedRequest,response:&Value)->Result<()> {sql(db.execute("INSERT INTO request_receipts VALUES(?,?,?,?)",params![r.public_key,r.request_id,id("request",&r.unsigned())?,response.to_string()]))?;Ok(())}
    pub fn claim(&self,r:&SignedRequest,at:u64)->Result<Value>{self.claim_with_source(r,at,None)}
    pub fn claim_with_source(&self,r:&SignedRequest,at:u64,source:Option<&str>)->Result<Value>{r.authenticate("claim")?;root(&r.round_id)?;let commitment=text(&r.payload,"commitment")?;root(&commitment)?;
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}
        let round=Self::round(&tx,&r.round_id)?;let (status,deadline):(String,u64)=sql(tx.query_row("SELECT status,claim_deadline FROM target_rounds WHERE round_id=?",[&r.round_id],|x|Ok((x.get(0)?,x.get(1)?))))?;
        if status!="OPEN"||at>deadline{return Err("DEADLINE: new claims closed".into());}if at<num(&round["pre"],"openedAt")?{return Err("CLOCK_ROLLBACK: authority time".into());}
        let cid=p::claim_id(&r.round_id,&r.public_key,&commitment)?;
        if let Some(v)=sql(tx.query_row("SELECT receipt_json FROM candidate_claims WHERE claim_id=?",[&cid],|x|x.get::<_,String>(0)).optional())?{let response=parse(v)?;Self::remember(&tx,r,&response)?;sql(tx.commit())?;return Ok(response);}
        let queue:u32=sql(tx.query_row("SELECT COUNT(*) FROM candidate_claims WHERE round_id=? AND status IN ('COMMITTED','REVEALED','VALID')",[&r.round_id],|x|x.get(0)))?;
        let own:u32=sql(tx.query_row("SELECT COUNT(*) FROM candidate_claims WHERE round_id=? AND miner_id=? AND status IN ('COMMITTED','REVEALED','VALID')",params![r.round_id,r.public_key],|x|x.get(0)))?;
        if queue as u64>=num(&round["pre"]["difficultyPolicy"],"maxQueue")?||own as u64>=num(&round["pre"]["difficultyPolicy"],"perIdentityClaims")?{return Err("BACKPRESSURE: claim queue quota".into());}
        if round["pre"]["difficultyPolicy"]["admission"]["version"]=="bounded-resources-v1" {if let Some(source)=source {
            let used:u64=sql(tx.query_row("SELECT COUNT(*) FROM candidate_admission_sources s JOIN candidate_claims c USING(claim_id) WHERE s.source_hash=? AND c.status IN ('COMMITTED','REVEALED')",[source],|r|r.get(0)))?;
            if used>=2{return Err("BACKPRESSURE: shared source has two pending claims; finish existing upload or wait for deadline; source quota is not independent identity proof".into());}
        }}
        let global:u32=sql(tx.query_row("SELECT COUNT(*) FROM candidate_claims WHERE status IN ('COMMITTED','REVEALED')",[],|r|r.get(0)))?;
        if global>=self.config.max_queue {return Err("BACKPRESSURE: global pending claim capacity; retry after earliest reveal/verification expiry".into());}
        let seq:u64=sql(tx.query_row("SELECT COALESCE(MAX(claim_sequence),0)+1 FROM candidate_claims WHERE round_id=?",[&r.round_id],|x|x.get(0)))?;
        let reveal=num(&round["pre"],"revealDeadline")?.min(at+num(&round["pre"]["difficultyPolicy"],"revealSeconds")?);let verification=num(&round["pre"],"verificationDeadline")?.min(reveal+num(&round["pre"]["difficultyPolicy"],"verificationSeconds")?);
        let receipt=self.signed("claim-receipt",json!({"schema":"flypow-claim-receipt-v2","networkId":self.config.network_id,"authorityId":self.authority_id,"roundId":r.round_id,"claimId":cid,"minerId":r.public_key,"commitment":commitment,"claimSequence":seq,"receivedAt":at,"revealDeadline":reveal,"verificationDeadline":verification}))?;
        sql(tx.execute("INSERT INTO candidate_claims VALUES(?,?,?,?,?,?,?,?,'COMMITTED',?)",params![cid,r.round_id,r.public_key,commitment,seq,at,reveal,verification,receipt.to_string()]))?;
        if let Some(source)=source {sql(tx.execute("INSERT OR IGNORE INTO candidate_admission_sources VALUES(?,?,?)",params![cid,source,at]))?;}
        Self::remember(&tx,r,&receipt)?;self.event(&tx,Some(&r.round_id),"CLAIM_ACCEPTED",json!({"claimId":cid,"claimSequence":seq}),at)?;sql(tx.commit())?;Ok(receipt)
    }
    fn owned_claim(db:&Connection,cid:&str,miner:&str,round:&str)->Result<(String,u64,u64)>{root(cid)?;let (m,r,s,d,v):(String,String,String,u64,u64)=sql(db.query_row("SELECT miner_id,round_id,status,reveal_deadline,verification_deadline FROM candidate_claims WHERE claim_id=?",[cid],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?))))?;if m!=miner||r!=round{return Err("AUTHORIZATION: claim owner/round".into());}Ok((s,d,v))}
    pub fn claim_state(&self,cid:&str)->Result<Value>{root(cid)?;let db=self.lock()?;let (receipt,status):(String,String)=sql(db.query_row("SELECT receipt_json,status FROM candidate_claims WHERE claim_id=?",[cid],|x|Ok((x.get(0)?,x.get(1)?))).optional())?.ok_or("NOT_FOUND: claim")?;let votes:u64=sql(db.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=?",[cid],|x|x.get(0)))?;let valid:u64=sql(db.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=? AND valid=1",[cid],|x|x.get(0)))?;let queue:u64=sql(db.query_row("SELECT COUNT(*) FROM verification_jobs j JOIN candidate_claims c USING(claim_id) WHERE claim_id=? AND c.status='REVEALED' AND c.verification_deadline>=? AND j.status IN ('PENDING','LEASED')",params![cid,now()],|x|x.get(0)))?;self.signed("claim-state",json!({"claimId":cid,"receipt":parse(receipt)?,"status":status,"verificationVotes":votes,"validVotes":valid,"invalidVotes":votes-valid,"quorum":2,"verificationQueue":queue,"terminalReason":match status.as_str(){"INVALID"=>Some("complete replay rejected"),"TIMED_OUT"=>Some("reveal or verification deadline expired"),_=>None},"serverTime":now()}))}

    pub fn upload_create(&self,r:&SignedRequest,at:u64)->Result<Value>{r.authenticate("upload-create")?;let cid=text(&r.payload,"claimId")?;let j=num(&r.payload,"trialIndex")?;let bytes=num(&r.payload,"bytes")?;let sha=text(&r.payload,"sha256")?;root(&sha)?;
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}
        let (status,deadline,_)=Self::owned_claim(&tx,&cid,&r.public_key,&r.round_id)?;let round=Self::round(&tx,&r.round_id)?;
        if status!="COMMITTED"||at>deadline{return Err("DEADLINE: private upload window".into());}if j>=num(&round["pre"],"requiredBackgrounds")?||bytes<480||bytes>num(&round["goal"],"maxTrialBytes")?{return Err("INVALID_INPUT: artifact size/index".into());}
        let old:Option<(String,u64,String)>=sql(tx.query_row("SELECT upload_id,bytes,sha256 FROM candidate_artifacts WHERE claim_id=? AND trial_index=?",params![cid,j],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?))).optional())?;
        let uid=id("artifact-upload",&json!({"claimId":cid,"trialIndex":j,"bytes":bytes,"sha256":sha}))?;
        if let Some((u,b,h))=old {if u!=uid||b!=bytes||h!=sha{return Err("CONFLICT: immutable artifact declaration".into());}}
        else {
            let incomplete:u64=sql(tx.query_row("SELECT COUNT(*) FROM candidate_artifacts WHERE status='UPLOADING'",[],|r|r.get(0)))?;
            if incomplete>=64 {return Err("BACKPRESSURE: incomplete upload capacity; resume an existing upload or wait for expiry".into());}
            let free=std::process::Command::new("df").args(["-Pk","--"]).arg(&self.data).output().ok().filter(|o|o.status.success()).and_then(|o|String::from_utf8(o.stdout).ok()).and_then(|s|s.lines().last()?.split_whitespace().nth(3)?.parse::<u64>().ok()).map(|kb|kb*1024);
            if free.is_none_or(|n|n<bytes.saturating_mul(2).saturating_add(32*1024*1024)) {return Err("BACKPRESSURE: disk reserve; retained results preserved, free disk capacity before retry".into());}
            let own:u64=sql(tx.query_row("SELECT COALESCE(SUM(bytes),0) FROM candidate_artifacts WHERE claim_id=?",[&cid],|x|x.get(0)))?;let total:u64=sql(tx.query_row("SELECT COALESCE(SUM(bytes),0) FROM candidate_artifacts WHERE status!='CLEANED'",[],|x|x.get(0)))?;
            if own+bytes>num(&round["goal"],"maxCandidateBytes")?||total+bytes>self.config.max_private_bytes{return Err("BACKPRESSURE: bounded private archive budget".into());}
            sql(tx.execute("INSERT INTO candidate_artifacts(upload_id,claim_id,miner_id,trial_index,bytes,sha256) VALUES(?,?,?,?,?,?)",params![uid,cid,r.public_key,j,bytes,sha]))?;
        }
        let result=self.signed("upload-receipt",json!({"uploadId":uid,"claimId":cid,"trialIndex":j,"bytes":bytes,"sha256":sha,"chunkBytes":CHUNK,"chunks":bytes.div_ceil(CHUNK as u64),"private":true}))?;Self::remember(&tx,r,&result)?;sql(tx.commit())?;Ok(result)
    }
    fn upload_owned(db:&Connection,uid:&str,r:&SignedRequest,at:u64)->Result<(u64,String,String)>{root(uid)?;
        let (cid,miner,bytes,sha,status):(String,String,u64,String,String)=sql(db.query_row("SELECT claim_id,miner_id,bytes,sha256,status FROM candidate_artifacts WHERE upload_id=?",[uid],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?))))?;
        if miner!=r.public_key{return Err("AUTHORIZATION: private artifact owner".into());}
        let (claim,deadline,_)=Self::owned_claim(db,&cid,&r.public_key,&r.round_id)?;
        if status=="CLEANED"||(status!="SEALED"&&(claim!="COMMITTED"||at>deadline)){return Err("DEADLINE: private artifact no longer mutable".into());}Ok((bytes,sha,status))
    }
    fn upload_dir(&self,uid:&str)->Result<PathBuf>{root(uid)?;Ok(self.data.join("private/artifacts").join(uid))}
    pub fn upload_chunk(&self,r:&SignedRequest,uid:&str,index:u64,bytes:&[u8],at:u64)->Result<Value>{r.authenticate("upload-chunk")?;let digest=hash(bytes);
        if text(&r.payload,"uploadId")?!=uid||num(&r.payload,"index")?!=index||num(&r.payload,"bytes")?!=bytes.len() as u64||text(&r.payload,"sha256")?!=digest{return Err("INVALID_INPUT: chunk signature/content binding".into());}
        let (total,_,status)={let db=self.lock()?;if let Some(v)=Self::cached(&db,r)?{return Ok(v);}Self::upload_owned(&db,uid,r,at)?};
        if index>=total.div_ceil(CHUNK as u64)||bytes.len() as u64!=(total-index*CHUNK as u64).min(CHUNK as u64){return Err("INVALID_INPUT: exact chunk boundary".into());}
        if status=="SEALED" {let db=self.lock()?;let old:Option<String>=sql(db.query_row("SELECT sha256 FROM artifact_chunks WHERE upload_id=? AND chunk_index=?",params![uid,index],|r|r.get(0)).optional())?;if old.as_deref()!=Some(&digest){return Err("CONFLICT: sealed chunk binding".into());}return self.signed("chunk-receipt",json!({"uploadId":uid,"index":index,"sha256":digest,"bytes":bytes.len(),"durable":true}));}
        let dir=self.upload_dir(uid)?;fs::create_dir_all(&dir).map_err(|e|e.to_string())?;let path=dir.join(format!("chunk-{index}.bin"));
        if path.exists(){if hash(&fs::read(&path).map_err(|e|e.to_string())?)!=digest{return Err("CONFLICT: existing durable chunk".into());}}
        else {if status=="SEALED"{return Err("CONFLICT: sealed archive immutable".into());}let temp=dir.join(format!("chunk-{index}-{}-{}.partial",r.request_id,random_suffix()?));let mut f=fs::OpenOptions::new().create_new(true).write(true).open(&temp).map_err(|e|e.to_string())?;f.write_all(bytes).map_err(|e|e.to_string())?;f.sync_all().map_err(|e|e.to_string())?;fs::rename(temp,&path).map_err(|e|e.to_string())?;sync_dir(&dir)?;}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}Self::upload_owned(&tx,uid,r,at)?;
        let existing:Option<String>=sql(tx.query_row("SELECT sha256 FROM artifact_chunks WHERE upload_id=? AND chunk_index=?",params![uid,index],|x|x.get(0)).optional())?;if existing.is_some_and(|h|h!=digest){return Err("CONFLICT: chunk metadata".into());}
        sql(tx.execute("INSERT OR IGNORE INTO artifact_chunks VALUES(?,?,?,?)",params![uid,index,bytes.len(),digest]))?;let result=self.signed("chunk-receipt",json!({"uploadId":uid,"index":index,"sha256":digest,"bytes":bytes.len(),"durable":true}))?;Self::remember(&tx,r,&result)?;sql(tx.commit())?;Ok(result)
    }
    pub fn upload_status(&self,r:&SignedRequest,uid:&str)->Result<Value>{r.authenticate("upload-status")?;if text(&r.payload,"uploadId")?!=uid{return Err("INVALID_INPUT: upload status binding".into());}let db=self.lock()?;let (total,sha,status)=Self::upload_owned(&db,uid,r,now())?;let mut q=sql(db.prepare("SELECT chunk_index FROM artifact_chunks WHERE upload_id=? ORDER BY chunk_index"))?;let rows=sql(q.query_map([uid],|x|x.get::<_,u64>(0)))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;self.signed("upload-state",json!({"uploadId":uid,"bytes":total,"sha256":sha,"status":status,"receivedChunks":rows,"serverTime":now()}))}
    pub fn seal(&self,r:&SignedRequest,uid:&str,at:u64)->Result<Value>{r.authenticate("upload-seal")?;if text(&r.payload,"uploadId")?!=uid{return Err("INVALID_INPUT: seal binding".into());}
        let (total,sha,status)={let db=self.lock()?;if let Some(v)=Self::cached(&db,r)?{return Ok(v);}Self::upload_owned(&db,uid,r,at)?};let dir=self.upload_dir(uid)?;let final_path=dir.join("response.bin");
        if status!="SEALED"{
            let chunks={let db=self.lock()?;let mut q=sql(db.prepare("SELECT chunk_index,bytes,sha256 FROM artifact_chunks WHERE upload_id=? ORDER BY chunk_index"))?;let rows=sql(q.query_map([uid],|x|Ok((x.get::<_,u64>(0)?,x.get::<_,u64>(1)?,x.get::<_,String>(2)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
            if chunks.len() as u64!=total.div_ceil(CHUNK as u64){return Err("UNSEALED: missing durable chunks".into());}
            let temp=dir.join(format!("seal-{}-{}.partial",r.request_id,random_suffix()?));let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&temp).map_err(|e|e.to_string())?;let mut h=Sha256::new();let mut written=0u64;
            for (expected,(index,len,digest)) in chunks.iter().enumerate(){if *index!=expected as u64{return Err("UNSEALED: chunk gap".into());}let bytes=fs::read(dir.join(format!("chunk-{index}.bin"))).map_err(|e|e.to_string())?;if bytes.len() as u64!=*len||hash(&bytes)!=*digest{return Err("DAMAGED_ARTIFACT: durable chunk hash".into());}h.update(&bytes);f.write_all(&bytes).map_err(|e|e.to_string())?;written+=*len;}
            if written!=total||p::hex(&h.finalize())!=sha{return Err("DAMAGED_ARTIFACT: complete hash".into());}f.sync_all().map_err(|e|e.to_string())?;fs::rename(temp,&final_path).map_err(|e|e.to_string())?;sync_dir(&dir)?;
        }
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}Self::upload_owned(&tx,uid,r,at)?;sql(tx.execute("UPDATE candidate_artifacts SET status='SEALED' WHERE upload_id=?",[uid]))?;
        let result=self.signed("seal-receipt",json!({"uploadId":uid,"status":"SEALED","sha256":sha,"bytes":total,"private":true}))?;Self::remember(&tx,r,&result)?;sql(tx.commit())?;Ok(result)
    }
    pub fn reveal(&self,r:&SignedRequest,cid:&str,at:u64)->Result<Value>{r.authenticate("reveal")?;if text(&r.payload,"claimId")?!=cid{return Err("INVALID_INPUT: reveal claim binding".into());}let manifest:CandidateManifest=serde_json::from_value(r.payload["manifest"].clone()).map_err(|e|e.to_string())?;let salt=text(&r.payload,"salt")?;
        let (round,uploads)={let db=self.lock()?;if let Some(v)=Self::cached(&db,r)?{return Ok(v);}if let Some(v)=sql(db.query_row("SELECT manifest_json,salt FROM candidate_reveals WHERE claim_id=?",[cid],|x|Ok((x.get::<_,String>(0)?,x.get::<_,String>(1)?))).optional())? {Self::owned_claim(&db,cid,&r.public_key,&r.round_id)?;if parse(v.0)?!=value(&manifest)||v.1!=salt{return Err("CONFLICT: immutable reveal".into());}return self.signed("reveal-receipt",json!({"claimId":cid,"status":"REVEALED","manifestHash":id("candidate-manifest",&value(&manifest))?,"independentlyReplayed":false,"serverTime":at}));}let (status,deadline,_)=Self::owned_claim(&db,cid,&r.public_key,&r.round_id)?;if status!="COMMITTED"||at>deadline{return Err("DEADLINE: reveal window".into());}
            let round=Self::round(&db,&r.round_id)?;p::validate_manifest(&manifest,&round)?;let committed:String=sql(db.query_row("SELECT commitment FROM candidate_claims WHERE claim_id=?",[cid],|x|x.get(0)))?;
            if p::commitment(&round,&r.public_key,&manifest,&salt)?!=committed{return Err("CONFLICT: revealed commitment".into());}
            let mut q=sql(db.prepare("SELECT upload_id,trial_index,bytes,sha256,status FROM candidate_artifacts WHERE claim_id=? ORDER BY trial_index"))?;
            let uploads=sql(q.query_map([cid],|x|Ok((x.get::<_,String>(0)?,x.get::<_,usize>(1)?,x.get::<_,u64>(2)?,x.get::<_,String>(3)?,x.get::<_,String>(4)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;(round,uploads)};
        if uploads.len()!=manifest.trials.len(){return Err("UNSEALED: missing candidate artifacts".into());}
        let goal:GoalSpec=serde_json::from_value(round["goal"].clone()).map_err(|e|e.to_string())?;
        // Full event check outside the write transaction, before replay job admission.
        for (j,(uid,index,bytes,sha,status)) in uploads.iter().enumerate(){let t=&manifest.trials[j];if *index!=j||*bytes!=t.bytes||*sha!=t.result_root||status!="SEALED"{return Err("UNSEALED: artifact/manifest mismatch".into());}let file=fs::read(self.upload_dir(uid)?.join("response.bin")).map_err(|e|e.to_string())?;
            if file.len() as u64!=*bytes||hash(&file)!=*sha||p::evaluate(&goal,&manifest.input,&file)?!=t.metrics{return Err("INVALID_INPUT: complete archive metrics mismatch".into());}}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}let (status,deadline,_)=Self::owned_claim(&tx,cid,&r.public_key,&r.round_id)?;if status!="COMMITTED"||at>deadline{return Err("DEADLINE: reveal no longer eligible".into());}
        let mh=id("candidate-manifest",&value(&manifest))?;sql(tx.execute("INSERT INTO candidate_reveals VALUES(?,?,?,?,?)",params![cid,serde_json::to_string(&manifest).unwrap(),mh,salt,at]))?;
        sql(tx.execute("INSERT OR IGNORE INTO candidate_inputs VALUES(?,?,?)",params![manifest.candidate_id,manifest.round_id,serde_json::to_string(&manifest.input).unwrap()]))?;
        sql(tx.execute("UPDATE candidate_claims SET status='REVEALED' WHERE claim_id=?",[cid]))?;
        for verifier in &self.config.verifier_keys {let job=id("verification-job",&json!({"claimId":cid,"verifierId":verifier}))?;sql(tx.execute("INSERT INTO verification_jobs(job_id,claim_id,verifier_id) VALUES(?,?,?)",params![job,cid,verifier]))?;}
        let result=self.signed("reveal-receipt",json!({"claimId":cid,"status":"REVEALED","manifestHash":mh,"independentlyReplayed":false,"serverTime":at}))?;Self::remember(&tx,r,&result)?;self.event(&tx,Some(&r.round_id),"CANDIDATE_REVEALED",json!({"claimId":cid,"candidateId":manifest.candidate_id,"verification":"pending-full-replay"}),at)?;sql(tx.commit())?;Ok(result)
    }
    pub fn lease(&self,r:&SignedRequest,at:u64)->Result<Value>{r.authenticate("verifier-lease")?;if !self.config.verifier_keys.contains(&r.public_key){return Err("AUTHORIZATION: verifier admission".into());}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;
        let model=&r.payload["modelReadiness"];let ready=if model.is_object(){let g:Value=parse(sql(tx.query_row("SELECT spec_json FROM goal_specs LIMIT 1",[],|r|r.get(0)))?)?;model["graphRoot"]==g["graphRoot"]&&model["modelDataRoot"]==g["modelDataRoot"]&&model["nativeBinaryReady"]==true}else{false};
        sql(tx.execute("INSERT INTO verifier_presence(verifier_id,last_seen,phase,model_json) VALUES(?,?,?,?) ON CONFLICT(verifier_id) DO UPDATE SET last_seen=excluded.last_seen,phase=excluded.phase,model_json=excluded.model_json",params![r.public_key,at,if ready{"model-checked"}else{"connected-unreported-model"},if model.is_object(){model.to_string()}else{"{}".into()}]))?;
        // Lease retries query current fencing state; a new lease is never invented
        // from a stale saved reply. Expired workers cannot overwrite successors.
        let selected:Option<(String,String,u64)>=sql(tx.query_row("SELECT j.job_id,j.claim_id,j.fencing_token FROM verification_jobs j JOIN candidate_claims c USING(claim_id) WHERE j.verifier_id=? AND c.status='REVEALED' AND c.verification_deadline>=? AND (j.status='PENDING' OR (j.status='LEASED' AND j.lease_until<?)) ORDER BY c.received_at,c.claim_sequence LIMIT 1",params![r.public_key,at,at],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?))).optional())?;
        let Some((job,cid,token))=selected else{sql(tx.commit())?;return self.signed("verification-lease",json!({"job":null,"serverTime":at}));};
        let concurrent:u64=sql(tx.query_row("SELECT COUNT(*) FROM verification_jobs WHERE status='LEASED' AND lease_until>=?",[at],|r|r.get(0)))?;
        if concurrent>=3 {sql(tx.commit())?;return self.signed("verification-lease",json!({"job":null,"serverTime":at,"reason":"concurrent-replay-capacity"}));}
        let (rid,deadline):(String,u64)=sql(tx.query_row("SELECT round_id,verification_deadline FROM candidate_claims WHERE claim_id=?",[&cid],|x|Ok((x.get(0)?,x.get(1)?))))?;
        let round=Self::round(&tx,&rid)?;let manifest=parse(sql(tx.query_row("SELECT manifest_json FROM candidate_reveals WHERE claim_id=?",[&cid],|x|x.get(0)))?)?;
        let mut q=sql(tx.prepare("SELECT upload_id,trial_index FROM candidate_artifacts WHERE claim_id=? AND status='SEALED' ORDER BY trial_index"))?;let artifacts=sql(q.query_map([&cid],|x|Ok(json!({"uploadId":x.get::<_,String>(0)?,"trialIndex":x.get::<_,u64>(1)?}))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;drop(q);
        let until=deadline.min(at+300);sql(tx.execute("UPDATE verification_jobs SET status='LEASED',fencing_token=fencing_token+1,lease_until=? WHERE job_id=?",params![until,job]))?;
        let result=self.signed("verification-lease",json!({"job":{"jobId":job,"claimId":cid,"roundId":rid,"fencingToken":token+1,"leaseUntil":until,"round":round,"manifest":manifest,"artifacts":artifacts},"serverTime":at}))?;sql(tx.commit())?;Ok(result)
    }
    pub fn heartbeat(&self,r:&SignedRequest,at:u64)->Result<Value>{r.authenticate("verifier-heartbeat")?;let job=text(&r.payload,"jobId")?;let token=num(&r.payload,"fencingToken")?;let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;
        let (owner,fence,until,deadline,status):(String,u64,u64,u64,String)=sql(tx.query_row("SELECT j.verifier_id,j.fencing_token,j.lease_until,c.verification_deadline,j.status FROM verification_jobs j JOIN candidate_claims c USING(claim_id) WHERE j.job_id=?",[&job],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?))))?;
        if owner!=r.public_key||token!=fence||until<at||deadline<at||status!="LEASED"{return Err("STALE_LEASE: fencing token/owner".into());}sql(tx.execute("UPDATE verifier_presence SET last_seen=? WHERE verifier_id=?",params![at,r.public_key]))?;let next=deadline.min(at+300);sql(tx.execute("UPDATE verification_jobs SET lease_until=? WHERE job_id=?",params![next,job]))?;sql(tx.commit())?;self.signed("verification-heartbeat",json!({"jobId":job,"fencingToken":token,"leaseUntil":next}))
    }
    pub fn verifier_artifact(&self,r:&SignedRequest,uid:&str,at:u64)->Result<Vec<u8>>{r.authenticate("verifier-artifact")?;if text(&r.payload,"uploadId")?!=uid{return Err("INVALID_INPUT: artifact binding".into());}root(uid)?;let job=text(&r.payload,"jobId")?;let token=num(&r.payload,"fencingToken")?;
        let db=self.lock()?;let (owner,fence,until,rid,status,sha):(String,u64,u64,String,String,String)=sql(db.query_row("SELECT j.verifier_id,j.fencing_token,j.lease_until,c.round_id,a.status,a.sha256 FROM verification_jobs j JOIN candidate_claims c USING(claim_id) JOIN candidate_artifacts a USING(claim_id) WHERE j.job_id=? AND a.upload_id=?",params![job,uid],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?))))?;
        if owner!=r.public_key||fence!=token||until<at||rid!=r.round_id||status!="SEALED"{return Err("AUTHORIZATION: private verifier artifact/lease".into());}drop(db);let bytes=fs::read(self.upload_dir(uid)?.join("response.bin")).map_err(|e|e.to_string())?;if hash(&bytes)!=sha{return Err("DAMAGED_ARTIFACT: verifier source".into());}Ok(bytes)
    }
    pub fn vote(&self,r:&SignedRequest,at:u64)->Result<Value>{r.authenticate("verifier-vote")?;if !self.config.verifier_keys.contains(&r.public_key){return Err("AUTHORIZATION: verifier vote".into());}
        let job=text(&r.payload,"jobId")?;let token=num(&r.payload,"fencingToken")?;let valid=r.payload["valid"].as_bool().ok_or("INVALID_INPUT: vote validity")?;
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}
        let (owner,fence,until,cid,rid,deadline,status):(String,u64,u64,String,String,u64,String)=sql(tx.query_row("SELECT j.verifier_id,j.fencing_token,j.lease_until,j.claim_id,c.round_id,c.verification_deadline,j.status FROM verification_jobs j JOIN candidate_claims c USING(claim_id) WHERE j.job_id=?",[&job],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?,x.get(5)?,x.get(6)?))))?;
        let round=Self::round(&tx,&rid)?;let manifest=parse(sql(tx.query_row("SELECT manifest_json FROM candidate_reveals WHERE claim_id=?",[&cid],|x|x.get(0)))?)?;
        if let Some(saved)=sql(tx.query_row("SELECT vote_json FROM verification_votes WHERE claim_id=? AND verifier_id=?",params![cid,r.public_key],|x|x.get::<_,String>(0)).optional())? {
            let prior:SignedRequest=serde_json::from_str(&saved).map_err(|e|e.to_string())?;
            if prior.round_id!=r.round_id||prior.payload!=r.payload{return Err("CONFLICT: immutable signed vote".into());}
            let yes:u32=sql(tx.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=? AND valid=1",[&cid],|x|x.get(0)))?;
            let no:u32=sql(tx.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=? AND valid=0",[&cid],|x|x.get(0)))?;
            let result=self.signed("vote-receipt",json!({"claimId":cid,"verifierId":r.public_key,"accepted":true,"validVotes":yes,"invalidVotes":no,"serverTime":at}))?;
            Self::remember(&tx,r,&result)?;sql(tx.commit())?;return Ok(result);
        }
        if owner!=r.public_key||rid!=r.round_id||token!=fence||until<at||at>deadline||status!="LEASED"{return Err("STALE_LEASE: vote identity/deadline".into());}
        for (field,expected) in [("networkId",json!(self.config.network_id)),("claimId",json!(cid)),("roundId",json!(rid)),("goalId",round["pre"]["goalId"].clone()),("candidateId",manifest["candidateId"].clone()),("goalResultRoot",manifest["goalResultRoot"].clone()),("manifestHash",json!(id("candidate-manifest",&manifest)?)),("evaluatorVersion",round["goal"]["evaluatorVersion"].clone()),("difficultyPolicyHash",round["pre"]["difficultyPolicyHash"].clone()),("verificationPolicyHash",json!(id("verification-policy",&round["pre"]["verificationPolicy"])?)),("completeTrials",round["pre"]["requiredBackgrounds"].clone())]{if r.payload[field]!=expected{return Err(format!("INVALID_INPUT: vote binding {field}"));}}
        if r.payload["fullReplay"]!=true{return Err("INVALID_INPUT: full replay attestation required".into());}
        let prior:Option<String>=sql(tx.query_row("SELECT vote_json FROM verification_votes WHERE claim_id=? AND verifier_id=?",params![cid,r.public_key],|x|x.get(0)).optional())?;
        if prior.is_some(){return Err("CONFLICT: verifier already voted".into());}
        sql(tx.execute("INSERT INTO verification_votes VALUES(?,?,?,?,?)",params![cid,r.public_key,valid,serde_json::to_string(r).unwrap(),at]))?;sql(tx.execute("UPDATE verification_jobs SET status='DONE' WHERE job_id=? AND fencing_token=?",params![job,token]))?;
        let yes:u32=sql(tx.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=? AND valid=1",[&cid],|x|x.get(0)))?;let no:u32=sql(tx.query_row("SELECT COUNT(*) FROM verification_votes WHERE claim_id=? AND valid=0",[&cid],|x|x.get(0)))?;
        if yes>=2||no>=2 {sql(tx.execute("UPDATE candidate_claims SET status=? WHERE claim_id=? AND status='REVEALED'",params![if yes>=2{"VALID"}else{"INVALID"},cid]))?;}
        self.public_vote_tx(&tx,r,at,false)?;self.finalize_tx(&tx,&rid,at)?;let result=self.signed("vote-receipt",json!({"claimId":cid,"verifierId":r.public_key,"accepted":true,"validVotes":yes,"invalidVotes":no,"serverTime":at}))?;Self::remember(&tx,r,&result)?;self.event(&tx,Some(&rid),"VERIFICATION_VOTE_ACCEPTED",json!({"claimId":cid,"validVotes":yes,"invalidVotes":no}),at)?;sql(tx.commit())?;Ok(result)
    }
    pub(super) fn public_vote_tx(&self,tx:&Connection,r:&SignedRequest,at:u64,backfilled:bool)->Result<()> {
        r.authenticate("verifier-vote")?;let cid=text(&r.payload,"claimId")?;
        let source=id("authority-action",&r.unsigned())?;
        let statement=self.signed("public-verification-declaration-v1",json!({"schema":"flybrain-public-verification-declaration-v1","authorityId":self.authority_id,"networkId":self.config.network_id,"roundId":r.round_id,"claimId":cid,"verifierId":r.public_key,"sourceSignedMessageHash":source,"valid":r.payload["valid"],"fullReplay":r.payload["fullReplay"],"completeTrials":r.payload["completeTrials"],"goalResultRoot":r.payload["goalResultRoot"],"verificationPolicyHash":r.payload["verificationPolicyHash"],"signedAt":at,"backfilledAt":if backfilled{Some(at)}else{None},"scope":"authority declaration of a verified admitted signature; original lease envelope stays private; does not claim biological validation"}))?;
        sql(tx.execute("INSERT OR IGNORE INTO public_verification_declarations VALUES(?,?,?,?,?)",params![cid,r.public_key,source,statement.to_string(),at]))?;Ok(())
    }
    fn finalize_tx(&self,tx:&Connection,rid:&str,at:u64)->Result<()> {
        let (status,version,goal,opened):(String,u64,String,u64)=sql(tx.query_row("SELECT status,version,goal_id,opened_at FROM target_rounds WHERE round_id=?",[rid],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?))))?;if !["OPEN","VERIFYING"].contains(&status.as_str()){return Ok(());}
        // The first still eligible sequence blocks every later verified claim.
        let first:Option<(String,String,u64,String,u64)>=sql(tx.query_row("SELECT claim_id,status,claim_sequence,miner_id,received_at FROM candidate_claims WHERE round_id=? AND status IN ('COMMITTED','REVEALED','VALID') ORDER BY claim_sequence LIMIT 1",[rid],|x|Ok((x.get(0)?,x.get(1)?,x.get(2)?,x.get(3)?,x.get(4)?))).optional())?;
        let Some((cid,claim_status,seq,miner,received))=first else{return Ok(());};if claim_status!="VALID"{return Ok(());}if received<opened{return Err("CLOCK_ROLLBACK: discovery timing".into());}
        let m=parse(sql(tx.query_row("SELECT manifest_json FROM candidate_reveals WHERE claim_id=?",[&cid],|x|x.get(0)))?)?;let round=Self::round(tx,rid)?;
        let winner=self.signed("round-winner",json!({"schema":"flypow-round-winner-v2","networkId":self.config.network_id,"authorityId":self.authority_id,"roundId":rid,"goalId":goal,"claimId":cid,"claimSequence":seq,"minerId":miner,"candidateId":m["candidateId"],"goalResultRoot":m["goalResultRoot"],"receivedAt":received,"confirmedAt":at,"independentlyReplayed":true,"replayPolicy":round["pre"]["verificationPolicy"],"payment":false,"rewards":false}))?;
        let changed=sql(tx.execute("UPDATE target_rounds SET status='FINALIZED',version=version+1 WHERE round_id=? AND version=? AND status IN ('OPEN','VERIFYING')",params![rid,version]))?;if changed!=1{return Err("CONFLICT: round state version".into());}
        sql(tx.execute("INSERT INTO round_winners VALUES(?,?,?)",params![rid,cid,winner.to_string()]))?;sql(tx.execute("UPDATE goal_plan_progress SET state='SOLVED',winner_round=? WHERE campaign_id=? AND goal_id=? AND state='PENDING'",params![rid,self.config.campaign_id,goal]))?;
        self.product_capture_tx(tx,rid,&cid,at)?;self.observe_tx(tx,rid,Some((cid,received,at)),true,at)?;self.event(tx,Some(rid),"ROUND_FINALIZED",winner,at)
    }
    fn observe_tx(&self,tx:&Connection,rid:&str,success:Option<(String,u64,u64)>,healthy:bool,at:u64)->Result<()> {
        let exists:u64=sql(tx.query_row("SELECT COUNT(*) FROM difficulty_observations WHERE round_id=?",[rid],|x|x.get(0)))?;if exists>0{return Ok(());}
        let round=Self::round(tx,rid)?;let opened=num(&round["pre"],"openedAt")?;let cal=parse(sql(tx.query_row("SELECT calibration_json FROM goal_specs WHERE goal_id=?",[text(&round["pre"],"goalId")?],|x|x.get(0)))?)?;let (frozen_family,levels,_)=Self::family_for(tx,&round["goal"],&cal)?;
        let stored:String=sql(tx.query_row("SELECT controller_json FROM difficulty_family_controllers WHERE campaign_id=? AND family_id=?",params![self.config.campaign_id,frozen_family],|x|x.get(0)))?;let mut c:Controller=serde_json::from_str(&stored).map_err(|e|e.to_string())?;
        let mut candidate=None;let mut discovery=None;let mut verification=None;
        if let Some((cid,received,confirmed))=success {let m=parse(sql(tx.query_row("SELECT manifest_json FROM candidate_reveals WHERE claim_id=?",[&cid],|x|x.get(0)))?)?;candidate=Some(id("scientific-input",&json!({"goalId":m["goalId"],"input":m["input"]}))?);discovery=Some(received.checked_sub(opened).ok_or("clock rollback")?*1000);verification=Some(confirmed.checked_sub(received).ok_or("clock rollback")?*1000);}
        let family=c.family_key.clone();if family!=frozen_family{return Err("controller does not match frozen round family".into());}let extension=&round["pre"]["difficultyPolicy"]["comparableFamily"];let normalized=if extension.is_object(){let numerator=num(extension,"normalizationNumerator")?;let denominator=num(extension,"normalizationDenominator")?;if denominator==0{return Err("invalid frozen normalization".into());}discovery.map(|ms|((ms as u128*numerator as u128/denominator as u128).min(86_400_000)) as u64)}else{discovery};c.observe(&levels,&family,at,normalized,healthy)?;let observation=json!({"discoveryMilliseconds":discovery,"normalizedDiscoveryMilliseconds":normalized,"comparableFamilyId":family,"postCommitMilliseconds":verification,"healthy":healthy,"controller":c,"timeSource":"authority-accepted-commitment-seconds","networkSpeed":"insufficient-evidence-until-16-comparable-rounds"});
        sql(tx.execute("INSERT INTO difficulty_observations VALUES(?,?,?,?,?,?)",params![rid,candidate,discovery,verification,healthy,observation.to_string()]))?;sql(tx.execute("UPDATE difficulty_snapshots SET controller_json=?,version=version+1 WHERE campaign_id=?",params![serde_json::to_string(&c).unwrap(),self.config.campaign_id]))?;sql(tx.execute("UPDATE difficulty_family_controllers SET controller_json=?,version=version+1 WHERE campaign_id=? AND family_id=?",params![serde_json::to_string(&c).unwrap(),self.config.campaign_id,family]))?;Ok(())
    }
    pub fn readiness(&self)->Result<Value> {
        // Queries only: no maintain(), round creation, heartbeat or test claim.
        let db=self.lock()?;let at=now();let (state,count):(String,u64)=sql(db.query_row("SELECT state,(SELECT COUNT(*) FROM target_rounds WHERE campaign_id=?) FROM target_campaigns WHERE campaign_id=?",params![self.config.campaign_id,self.config.campaign_id],|r|Ok((r.get(0)?,r.get(1)?))))?;
        let active:Option<String>=sql(db.query_row("SELECT descriptor_json FROM target_rounds WHERE campaign_id=? AND status IN ('OPEN','VERIFYING')",[&self.config.campaign_id],|r|r.get(0)).optional())?;let round=active.map(parse).transpose()?;
        let reserved:u64=sql(db.query_row("SELECT COALESCE(SUM(bytes),0) FROM candidate_artifacts WHERE status!='CLEANED'",[],|r|r.get(0)))?;
        let mut verifiers=Vec::new();for key in &self.config.verifier_keys {let presence:Option<(u64,String,String)>=sql(db.query_row("SELECT last_seen,phase,model_json FROM verifier_presence WHERE verifier_id=?",[key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional())?;let ready=presence.as_ref().is_some_and(|p|p.0+90>=at&&p.1=="model-checked");verifiers.push(json!({"verifierId":key,"connected":presence.as_ref().is_some_and(|p|p.0+90>=at),"modelReadyReported":ready,"lastSeen":presence.as_ref().map(|p|p.0),"source":"authorized signed verifier lease/heartbeat; not proof of independent operators"}));}
        let free=std::process::Command::new("df").args(["-Pk","--"]).arg(&self.data).output().ok().filter(|o|o.status.success()).and_then(|o|String::from_utf8(o.stdout).ok()).and_then(|s|s.lines().last()?.split_whitespace().nth(3)?.parse::<u64>().ok()).map(|kb|kb*1024);
        let successful_replays:u64=sql(db.query_row("SELECT COUNT(*) FROM verification_votes WHERE valid=1",[],|r|r.get(0)))?;let journal:String=sql(db.query_row("PRAGMA journal_mode",[],|r|r.get(0)))?;let capabilities=self.capabilities(&db,round.as_ref())?;
        let mut readiness=json!({"schema":"flypow-target-readiness-v1","networkId":self.config.network_id,"authorityId":self.authority_id,"campaignId":self.config.campaign_id,"serverTime":at,"state":state,"roundId":round.as_ref().map(|r|r["roundId"].clone()),"round":round,"roundCount":count,"capabilities":capabilities,"database":{"persistent":true,"journalMode":journal},"verifiers":verifiers,"archiveSpace":{"configuredCapBytes":self.config.max_private_bytes,"reservedBytes":reserved,"remainingDeclaredBytes":self.config.max_private_bytes.saturating_sub(reserved),"freeFilesystemBytes":free,"freeSource":"df -Pk at query time","physicalCandidateBytes":sql(db.query_row("SELECT COALESCE(SUM(physical_bytes),0) FROM artifact_lifecycle",[],|r|r.get::<_,u64>(0)))?.to_string(),"temporaryCandidateBytes":sql(db.query_row("SELECT COALESCE(SUM(temp_bytes),0) FROM artifact_lifecycle",[],|r|r.get::<_,u64>(0)))?.to_string(),"publicObjectBytes":sql(db.query_row("SELECT COALESCE(SUM(bytes),0) FROM public_objects",[],|r|r.get::<_,u64>(0)))?.to_string(),"databaseBytes":fs::metadata(self.data.join("target-v2.sqlite")).ok().map(|m|m.len().to_string()),"walBytes":fs::metadata(self.data.join("target-v2.sqlite-wal")).ok().map(|m|m.len().to_string()),"evidenceRetention":"sealed/winning/public/referenced evidence retained; only redundant chunks and expired incomplete bytes reclaimed","capacityCondition":"new candidate declarations stop at cap or disk reserve; increase storage or explicitly archive retained evidence; no silent deletion"},"releaseSource":option_env!("FLYPOW_BUILD_REVISION").unwrap_or("unrecorded-build"),"readOnly":true,"authorizedFullReplayReports":successful_replays,"payment":false,"rewards":false,"supply":self.supply(&db)?});readiness.as_object_mut().unwrap().extend(self.product_identity(&db)?.as_object().unwrap().clone());self.signed("authority-readiness",readiness)
    }
    pub fn publish_plan(&self,r:&SignedRequest,at:u64)->Result<Value> {
        r.authenticate("publish-future-plan")?;if !self.config.admin_keys.contains(&r.public_key){return Err("AUTHORIZATION: plan admin".into());}
        let plan=&r.payload["plan"];if plan["schema"]!="flypow-target-plan-revision-v1"||!plan["source"].is_string(){return Err("INVALID_INPUT: versioned plan source required".into());}
        let goals=plan["append"].as_array().ok_or("INVALID_INPUT: appended goals")?;if goals.is_empty()||goals.len()>128||plan["source"].as_str().is_none_or(|s|s.is_empty()||s.len()>2048){return Err("INVALID_INPUT: future plan size".into());}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}
        let previous:Option<String>=sql(tx.query_row("SELECT plan_hash FROM goal_plan_revisions WHERE campaign_id=? ORDER BY revision DESC LIMIT 1",[&self.config.campaign_id],|x|x.get(0)).optional())?;if plan["previousPlanHash"]!=json!(previous){return Err("CONFLICT: future plan revision chain".into());}
        let revision:u64=sql(tx.query_row("SELECT COALESCE(MAX(revision),0)+1 FROM goal_plan_revisions WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)))?;if plan["revision"]!=revision{return Err("CONFLICT: future plan revision".into());}
        let mut index:u64=sql(tx.query_row("SELECT COALESCE(MAX(plan_index),0)+1 FROM goal_plan_progress WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)))?;
        let total:u64=sql(tx.query_row("SELECT COUNT(*) FROM goal_plan_progress WHERE campaign_id=?",[&self.config.campaign_id],|r|r.get(0)))?;if total+goals.len() as u64>4096{return Err("future plan total bound".into());}
        let mut scientific_tasks=Self::registered_scientific_tasks(&tx)?;
        for item in goals {let g:GoalSpec=serde_json::from_value(item["goal"].clone()).map_err(|e|e.to_string())?;g.validate()?;let c=&item["calibration"];let mut definition=value(&g);definition.as_object_mut().unwrap().remove("calibrationHash");
            if g.graph_root!="6c42f6ff8e2198aca17a765acae0475b490abb0169d615e32b71c976f563deb4"||g.neuron_count!=165122||c["schema"]!="flypow-target-calibration-v2"||hash(&canonical(c)?)!=g.calibration_hash||c["scientificDefinitionHash"]!=id("calibration-science",&definition)?||Self::levels(c)?.is_empty(){return Err("INVALID_INPUT: complete calibrated MaleCNS goal required".into());}
            let gid=g.goal_id()?;let existed:u64=sql(tx.query_row("SELECT COUNT(*) FROM goal_plan_progress WHERE campaign_id=? AND goal_id=?",params![self.config.campaign_id,gid],|r|r.get(0)))?;if existed>0{return Err("CONFLICT: plan cannot repeat an opened or solved goal".into());}
            if !scientific_tasks.insert(crate::product_identity::task(&g)?){return Err("CONFLICT: scientific task already registered; renaming does not create discovery supply".into());}
            sql(tx.execute("INSERT OR IGNORE INTO goal_specs VALUES(?,?,?)",params![gid,serde_json::to_string(&g).unwrap(),c.to_string()]))?;sql(tx.execute("INSERT INTO goal_plan_progress(campaign_id,plan_index,goal_id) VALUES(?,?,?)",params![self.config.campaign_id,index,gid]))?;index+=1;
        }
        if let Some(families)=plan["families"].as_array(){for f in families{let f:p::family::Family=serde_json::from_value(f.clone()).map_err(|e|e.to_string())?;Self::register_family(&tx,&f)?;}}
        let h=id("target-plan-revision",plan)?;sql(tx.execute("INSERT INTO goal_plan_revisions VALUES(?,?,?,?,?,?)",params![self.config.campaign_id,revision,h,plan.to_string(),serde_json::to_string(r).unwrap(),at]))?;
        let result=self.signed("plan-receipt",json!({"planHash":h,"revision":revision,"appendedGoals":goals.len(),"onlyUnopenedGoals":true,"publishedAt":at}))?;Self::remember(&tx,r,&result)?;sql(tx.execute("INSERT INTO target_audit(action,payload_json,at) VALUES('FUTURE_PLAN_APPENDED',?,?)",params![result.to_string(),at]))?;self.event(&tx,None,"FUTURE_PLAN_APPENDED",result.clone(),at)?;sql(tx.commit())?;Ok(result)
    }
    pub fn publish_policy(&self,r:&SignedRequest,at:u64)->Result<Value>{
        r.authenticate("publish-future-policy")?;if !self.config.admin_keys.contains(&r.public_key){return Err("AUTHORIZATION: future policy admin".into());}
        let mut proposed=self.config.clone();let policy=&r.payload["policy"];
        proposed.tau_seconds=num(policy,"tauSeconds")?;proposed.search_seconds=num(policy,"searchSeconds")?;
        proposed.reveal_seconds=num(policy,"revealSeconds")?;proposed.verification_seconds=num(policy,"verificationSeconds")?;
        proposed.max_queue=u32::try_from(num(policy,"maxQueue")?).map_err(|_|"INVALID_INPUT: queue")?;
        proposed.per_identity_claims=u32::try_from(num(policy,"perIdentityClaims")?).map_err(|_|"INVALID_INPUT: quota")?;proposed.validate()?;
        if canonical(policy)?!=canonical(&proposed.policy())?{return Err("INVALID_INPUT: only supported future policy fields are accepted".into());}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;let at=self.check_clock(&tx,at)?;if let Some(v)=Self::cached(&tx,r)?{return Ok(v);}
        let revision:u64=sql(tx.query_row("SELECT COALESCE(MAX(revision),0)+1 FROM target_future_policies WHERE campaign_id=?",[&self.config.campaign_id],|x|x.get(0)))?;
        let mut frozen=policy.clone();frozen["policyRevision"]=json!(revision);let h=id("difficulty-policy",&frozen)?;
        sql(tx.execute("INSERT INTO target_future_policies VALUES(?,?,?,?,?,?)",params![self.config.campaign_id,revision,h,frozen.to_string(),serde_json::to_string(r).unwrap(),at]))?;
        let result=self.signed("policy-receipt",json!({"policyHash":h,"policyRevision":revision,"onlyFutureRounds":true,"publishedAt":at}))?;
        sql(tx.execute("INSERT INTO target_audit(action,payload_json,at) VALUES('FUTURE_POLICY_PUBLISHED',?,?)",params![result.to_string(),at]))?;Self::remember(&tx,r,&result)?;
        self.event(&tx,None,"FUTURE_POLICY_PUBLISHED",result.clone(),at)?;sql(tx.commit())?;Ok(result)
    }
    pub fn events(&self,after:u64)->Result<Value>{let db=self.lock()?;let mut q=sql(db.prepare("SELECT e.payload_json FROM protocol_events e JOIN protocol_outbox o USING(event_sequence) WHERE e.event_sequence>? ORDER BY e.event_sequence LIMIT 128"))?;let rows=sql(q.query_map([after],|x|x.get::<_,String>(0)))?.map(|v|parse(v.map_err(|e|e.to_string())?)).collect::<Result<Vec<_>>>()?;let cursor=rows.last().and_then(|x|x["eventSequence"].as_u64()).unwrap_or(after);Ok(json!({"events":rows,"nextCursor":cursor,"committedOutbox":true}))}
    pub fn session(&self,r:&SignedRequest,at:u64)->Result<Value>{r.authenticate("session-heartbeat")?;let sid=text(&r.payload,"sessionId")?;let phase=text(&r.payload,"phase")?;if sid.len()>128||!["searching","computing","paused","offline","ended","domain-exhausted"].contains(&phase.as_str()){return Err("INVALID_INPUT: session phase".into());}let db=self.lock()?;
        sql(db.execute("INSERT INTO target_sessions VALUES(?,?,?,?,?) ON CONFLICT(miner_id,session_id) DO UPDATE SET round_id=excluded.round_id,phase=excluded.phase,last_seen=excluded.last_seen",params![r.public_key,sid,r.round_id,phase,at]))?;
        self.signed("session-receipt",json!({"sessionId":sid,"receivedAt":at,"expiresAt":at+45,"source":"signed-client-heartbeat-not-person-count"}))
    }
    pub fn broadcast_event(&self,event:Value){let _=self.event_bus.send(event);}
    pub fn stats(&self)->Result<Value>{self.statistics_at(now())}

}

#[derive(Debug)]struct ApiError(String);
impl IntoResponse for ApiError{fn into_response(self)->Response{let code=self.0.split(':').next().unwrap_or("INTERNAL").to_string();let status=match code.as_str(){"NOT_FOUND"=>StatusCode::NOT_FOUND,"BAD_SIGNATURE"|"AUTHORIZATION"=>StatusCode::FORBIDDEN,"CONFLICT"|"STALE_LEASE"=>StatusCode::CONFLICT,"DEADLINE"=>StatusCode::GONE,"BACKPRESSURE"=>StatusCode::TOO_MANY_REQUESTS,"DAMAGED_ARTIFACT"|"storage"|"NOT_CONFIGURED"=>StatusCode::SERVICE_UNAVAILABLE,"INVALID_INPUT"|"UNSEALED"=>StatusCode::BAD_REQUEST,_=>StatusCode::BAD_REQUEST};(status,Json(json!({"code":code,"message":self.0}))).into_response()}}
impl From<String> for ApiError{fn from(s:String)->Self{Self(s)}}
async fn blocking<T:Send+'static>(a:Arc<Authority>,f:impl FnOnce(&Authority)->Result<T>+Send+'static)->std::result::Result<T,ApiError>{tokio::task::spawn_blocking(move||f(&a)).await.map_err(|e|ApiError(e.to_string()))?.map_err(ApiError)}
async fn current(State(a):State<Arc<Authority>>)->std::result::Result<Json<Value>,ApiError>{blocking(a,|a|{a.current()}).await.map(Json)}
async fn round(State(a):State<Arc<Authority>>,Path(rid):Path<String>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.round_state(&rid)).await.map(Json)}
#[derive(Deserialize)]struct EventQuery{#[serde(default)]after:u64}
async fn events(State(a):State<Arc<Authority>>,Query(q):Query<EventQuery>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.events(q.after)).await.map(Json)}
async fn stats(State(a):State<Arc<Authority>>)->std::result::Result<Json<Value>,ApiError>{blocking(a,|a|a.stats()).await.map(Json)}
async fn readiness(State(a):State<Arc<Authority>>)->std::result::Result<Json<Value>,ApiError>{blocking(a,|a|a.readiness()).await.map(Json)}
async fn future_plan(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.publish_plan(&r,now())).await.map(Json)}
async fn claims(State(a):State<Arc<Authority>>,peer:Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,headers:HeaderMap,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{let source=product::source_key(&headers,peer.map(|p|p.0.0));blocking(a,move|a|a.claim_with_source(&r,now(),Some(&source))).await.map(Json)}
async fn claim_state(State(a):State<Arc<Authority>>,Path(cid):Path<String>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.claim_state(&cid)).await.map(Json)}
async fn reveal(State(a):State<Arc<Authority>>,Path(cid):Path<String>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.reveal(&r,&cid,now())).await.map(Json)}
async fn upload_create(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.upload_create(&r,now())).await.map(Json)}
async fn chunk(State(a):State<Arc<Authority>>,Path((uid,index)):Path<(String,u64)>,headers:HeaderMap,bytes:Bytes)->std::result::Result<Json<Value>,ApiError>{let r:SignedRequest=serde_json::from_str(headers.get("x-flypow-action").and_then(|v|v.to_str().ok()).ok_or_else(||ApiError("BAD_SIGNATURE: chunk action missing".into()))?).map_err(|e|ApiError(e.to_string()))?;blocking(a,move|a|a.upload_chunk(&r,&uid,index,&bytes,now())).await.map(Json)}
async fn upload_status(State(a):State<Arc<Authority>>,Path(uid):Path<String>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.upload_status(&r,&uid)).await.map(Json)}
async fn seal(State(a):State<Arc<Authority>>,Path(uid):Path<String>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.seal(&r,&uid,now())).await.map(Json)}
async fn lease(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.lease(&r,now())).await.map(Json)}
async fn heartbeat(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.heartbeat(&r,now())).await.map(Json)}
async fn vote(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.vote(&r,now())).await.map(Json)}
async fn artifact(State(a):State<Arc<Authority>>,Path(uid):Path<String>,Json(r):Json<SignedRequest>)->std::result::Result<Bytes,ApiError>{blocking(a,move|a|a.verifier_artifact(&r,&uid,now())).await.map(Bytes::from)}
#[derive(Deserialize)]struct HistoryQuery{#[serde(default)]before:u64,#[serde(default="history_limit")]limit:u64}
fn history_limit()->u64{20}
async fn history(State(a):State<Arc<Authority>>,Query(q):Query<HistoryQuery>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.round_history(q.before,q.limit)).await.map(Json)}
async fn work_report(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.report_work(&r,now())).await.map(Json)}
async fn session(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.session(&r,now())).await.map(Json)}
async fn future_policy(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.publish_policy(&r,now())).await.map(Json)}
async fn origin_guard(State(a):State<Arc<Authority>>,request:axum::extract::Request,next:axum::middleware::Next)->Response{
    let origin=request.headers().get("origin").cloned();let admitted=origin.as_ref().and_then(|v|v.to_str().ok()).is_some_and(|v|a.config.allowed_origins.iter().any(|o|o==v));
    if origin.is_some()&&!admitted{return ApiError("AUTHORIZATION: browser origin is not admitted".into()).into_response();}
    if request.method()!=Method::GET&&request.method()!=Method::HEAD&&!admitted&&request.headers().get("sec-fetch-site").and_then(|v|v.to_str().ok())==Some("cross-site"){return ApiError("AUTHORIZATION: cross-site action without admitted Origin".into()).into_response();}
    let preflight=request.method()==Method::OPTIONS;
    if preflight {
        let method=request.headers().get("access-control-request-method").and_then(|v|v.to_str().ok()).unwrap_or("");
        let headers=request.headers().get("access-control-request-headers").and_then(|v|v.to_str().ok()).unwrap_or("");
        if !admitted||!["GET","HEAD","POST","PUT"].contains(&method)||headers.split(',').map(|s|s.trim().to_ascii_lowercase()).any(|h|!h.is_empty()&&!["content-type","x-flypow-action","last-event-id"].contains(&h.as_str())){return ApiError("AUTHORIZATION: unsupported CORS preflight".into()).into_response();}
    }
    let mut response=if preflight {StatusCode::NO_CONTENT.into_response()}else{next.run(request).await};let h=response.headers_mut();if !h.contains_key("cache-control"){h.insert("cache-control",axum::http::HeaderValue::from_static("no-store"));}
    if admitted {h.insert("access-control-allow-origin",origin.unwrap());h.insert("vary",axum::http::HeaderValue::from_static("Origin"));if preflight{h.insert("access-control-allow-methods",axum::http::HeaderValue::from_static("GET, HEAD, POST, PUT"));h.insert("access-control-allow-headers",axum::http::HeaderValue::from_static("Content-Type, X-Flypow-Action, Last-Event-ID"));h.insert("access-control-max-age",axum::http::HeaderValue::from_static("600"));}}response
}
async fn event_stream(State(a):State<Arc<Authority>>,Query(q):Query<EventQuery>,headers:HeaderMap)->Sse<impl futures_util::Stream<Item=std::result::Result<Event,std::convert::Infallible>>>{
    let cursor=headers.get("last-event-id").and_then(|v|v.to_str().ok()).and_then(|v|v.parse::<u64>().ok()).unwrap_or(q.after).max(q.after);
    let rx=a.event_bus.subscribe();
    let stream=futures_util::stream::unfold((a,cursor,rx,std::collections::VecDeque::<Value>::new(),true),|(a,mut cursor,mut rx,mut pending,mut read)|async move{
        loop {if let Some(event)=pending.pop_front(){cursor=event["eventSequence"].as_u64().unwrap();let item=Event::default().id(cursor.to_string()).event("protocol-event").json_data(&event).unwrap();return Some((Ok(item),(a,cursor,rx,pending,read)));}
            if read {let copy=a.clone();if let Ok(Ok(v))=tokio::task::spawn_blocking(move||copy.events(cursor)).await{pending.extend(v["events"].as_array().unwrap().iter().cloned());read=v["events"].as_array().unwrap().len()==128;}else{read=false;}if !pending.is_empty(){continue;}}
            match rx.recv().await {Ok(e)=>{if e["eventSequence"].as_u64().unwrap_or(0)>cursor {if e["eventSequence"].as_u64()==Some(cursor+1){pending.push_back(e);}else{read=true;}}},Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>{read=true;},Err(_)=>return None}
        }
    });Sse::new(stream).keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(10)))
}

pub fn router(a:Arc<Authority>)->Router{Router::new().merge(market::routes()).merge(crate::explorer::routes()).merge(private_delivery::routes()).merge(product::routes()).merge(chain_reconciliation::routes()).merge(economic_ledger::routes()).merge(business_accounting::routes())
    .route("/api/target-mining/v2/rounds/current",get(current))
    .route("/api/target-mining/v2/rounds/{rid}",get(round))
    .route("/api/target-mining/v2/rounds/history",get(history))
    .route("/api/target-mining/v2/telemetry",post(work_report))
    .route("/api/target-mining/v2/events",get(events))
    .route("/api/target-mining/v2/events/stream",get(event_stream))
    .route("/api/target-mining/v2/admin/future-policy",post(future_policy))
    .route("/api/target-mining/v2/network-stats",get(stats))
    .route("/api/target-mining/v2/readiness",get(readiness))
    .route("/api/target-mining/v2/admin/future-plan",post(future_plan))
    .route("/api/target-mining/v2/claims",post(claims))
    .route("/api/target-mining/v2/claims/{cid}",get(claim_state))
    .route("/api/target-mining/v2/claims/{cid}/reveal",post(reveal))
    .route("/api/target-mining/v2/artifacts/uploads",post(upload_create))
    .route("/api/target-mining/v2/artifacts/uploads/{uid}/chunks/{index}",put(chunk))
    .route("/api/target-mining/v2/artifacts/uploads/{uid}/status",post(upload_status))
    .route("/api/target-mining/v2/artifacts/uploads/{uid}/seal",post(seal))
    .route("/api/target-mining/v2/verifier-jobs/lease",post(lease))
    .route("/api/target-mining/v2/verifier-jobs/heartbeat",post(heartbeat))
    .route("/api/target-mining/v2/verifier-artifacts/{uid}",post(artifact))
    .route("/api/target-mining/v2/verifier-votes",post(vote))
    .route("/api/target-mining/v2/sessions/heartbeat",post(session))
    .layer(DefaultBodyLimit::max(CHUNK+65536))
    .layer(axum::middleware::from_fn_with_state(a.clone(),origin_guard)).with_state(a)}
