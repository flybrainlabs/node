//! Threshold-attested, actual-context chain reconciliation. This adapter checks
//! raw account hashes and frozen liabilities; it does not pretend to fetch an
//! arbitrary historical snapshot or independently trust an RPC provider.
use super::*;
fn key_bytes(s:&str)->Result<Vec<u8>>{
 if s.len()==64&&root(s).is_ok(){return p::unhex(s);}
 let alphabet=b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";let mut bytes=vec![0u8];
 for ch in s.bytes(){let mut carry=alphabet.iter().position(|b|*b==ch).ok_or("INVALID_INPUT: base58")? as u32;for b in bytes.iter_mut().rev(){carry+=*b as u32*58;*b=(carry&255) as u8;carry>>=8;}while carry>0{bytes.insert(0,(carry&255) as u8);carry>>=8;}}
 let first=bytes.iter().position(|b|*b!=0).unwrap_or(bytes.len());let mut out=vec![0;s.bytes().take_while(|b|*b==b'1').count()];out.extend_from_slice(&bytes[first..]);if out.len()!=32{return Err("INVALID_INPUT: pubkey width".into());}Ok(out)
}
fn amount(bytes:&[u8],at:usize)->Result<u64>{Ok(u64::from_le_bytes(bytes.get(at..at+8).ok_or("INVALID_INPUT: account boundary")?.try_into().unwrap()))}
impl Authority{
 pub fn reconcile_chain_observation(&self,r:&SignedRequest,at:u64)->Result<Value>{
  r.authenticate("chain-reconciliation")?;if !self.config.admin_keys.contains(&r.public_key){return Err("AUTHORIZATION: chain reconciliation operator".into());}
  let config:Value=serde_json::from_slice(&fs::read(self.data.join("private/economic-settlement-config.json")).map_err(|_|"NOT_CONFIGURED: audited chain identity")?).map_err(|_|"config")?;
  let report=&r.payload["report"];if config["enabled"]!=true||report["genesisHash"]!=config["genesisHash"]||report["programId"]!=config["programId"]||report["mint"]!=config["mint"]||report["policyHash"]!=config["policyHash"]||report["commitment"]!="finalized" {return Err("INVALID_INPUT: frozen reconciliation identity/finality".into());}
  let observed=num(report,"observedAt")?;if observed>at+30||at>observed+600{return Err("DEADLINE: fresh chain reconciliation".into());}
  let message=p::unhex(&id("chain-reconciliation-observation-v1",report)?)?;let witnesses=r.payload["witnesses"].as_array().ok_or("BAD_SIGNATURE: chain observers")?;let mut keys=std::collections::BTreeSet::new();
  for witness in witnesses{let key=text(witness,"publicKey")?;if !self.config.verifier_keys.contains(&key)||!keys.insert(key.clone()){return Err("AUTHORIZATION: admitted distinct chain observers".into());}VerifyingKey::from_bytes(&p::unhex(&key)?.try_into().map_err(|_|"key")?).map_err(|_|"key")?.verify_strict(&message,&Signature::from_slice(&p::unhex(&text(witness,"signature")?)?).map_err(|_|"signature")?).map_err(|_|"BAD_SIGNATURE: chain observation")?;}if keys.len()<2{return Err("BAD_SIGNATURE: observer quorum".into());}
  let asset=text(&config,"asset")?;let ledger=self.economic_reconcile()?;let db=self.lock()?;let(state,book_root):(String,String)=sql(db.query_row("SELECT state,root FROM economic_books WHERE asset=?",[&asset],|r|Ok((r.get(0)?,r.get(1)?))))?;
  let book:flypow_economic_core::Book=serde_json::from_str(&state).map_err(|_|"book")?;let local=book.reconcile().is_ok()&&ledger["books"].as_array().is_some_and(|rows|rows.iter().any(|b|b["asset"]==asset&&b["localLedgerReconciled"]==true));let mut status="uncertain";let mut reasons=Vec::new();
  let accounts=report["accounts"].as_array().ok_or("INVALID_INPUT: observed accounts")?;if accounts.len()>256{return Err("INVALID_INPUT: reconciliation bounds".into());}let mut decoded=std::collections::BTreeMap::new();let mut contexts=std::collections::BTreeSet::new();
  for account in accounts{if account["commitment"]!="finalized"||account["method"]!="getMultipleAccountsInfoAndContext"{return Err("INVALID_INPUT: actual account read context required".into());}let context=text(account,"contextSlot")?;context.parse::<u64>().map_err(|_|"INVALID_INPUT: context")?;contexts.insert(context);
   let bytes=p::unhex(&text(account,"dataHex")?)?;if hash(&bytes)!=account["dataSha256"]{return Err("DAMAGED_ARTIFACT: observed account hash".into());}let address=text(account,"address")?;if decoded.insert(address,(text(account,"owner")?,bytes)).is_some(){return Err("INVALID_INPUT: repeated observed address".into());}
  }
  if contexts.len()!=1{reasons.push("distinct RPC contexts; uncertain view".to_string());}
  if report["bookRoot"]!=book_root||report["projectHistoryComplete"]!=true||report["projectionCaughtUp"]!=true{reasons.push("history gap or local projection has not reached the observed transaction waterline".into());status="syncing";}
  let get=|address:&str,owner:&str,tag:Option<&[u8]>|->Result<&[u8]>{let(o,b)=decoded.get(address).ok_or("CONDITIONS_REQUIRED: complete related account batch")?;if o!=owner||tag.is_some_and(|t|!b.starts_with(t)){return Err("INVALID_INPUT: observed owner/layout".into());}Ok(b)};
  let global=get(&text(&config,"global")?,&text(&config,"programId")?,Some(b"FLYGV002"))?;if global.len()!=512||global[40..72]!=key_bytes(&text(&config,"genesisHash")?)?||p::hex(&global[72..104])!=config["policyHash"]||global[200..232]!=key_bytes(&text(&config,"mint")?)?||global[232]!=1{return Err("INVALID_INPUT: global chain identity/layout".into());}
  let mint=get(&text(&config,"mint")?,"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",None)?;if mint.len()!=82||mint[44]!=8||mint[..4]!=[0;4]||mint[46..50]!=[0;4]||amount(mint,36)?!=flypow_economic_core::CAP{return Err("INVALID_INPUT: mint identity/authorities".into());}
  let vaults=config["vaults"].as_array().ok_or("INVALID_INPUT: configured vaults")?;if vaults.len()!=3{return Err("vaults".into());}
  for i in 0..3{let address=vaults[i].as_str().or_else(||vaults[i]["address"].as_str()).ok_or("vault address")?;let bytes=get(address,"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",None)?;if bytes.len()!=165||bytes[..32]!=key_bytes(&text(&config,"mint")?)?||bytes[32..64]!=key_bytes(&text(&config,"global")?)?{return Err("INVALID_INPUT: vault owner/mint".into());}if amount(bytes,64)?!=book.vaults[i].balance.0||amount(global,233+i*8)?!=book.vaults[i].free().map_err(|e|format!("book: {e}"))?{reasons.push("vault/allocation and local liabilities differ at observed waterline".into());}}
  for(key,stage)in &book.stages{
   let bytes=get(key,&text(&config,"programId")?,None)?;
   if bytes.len()!=256{return Err("INVALID_INPUT: stage account length".into());}
   if bytes.starts_with(b"FLYSV002"){reasons.push("legacy stage reservation counters unknown; audited inventory migration required".into());continue;}
   if !bytes.starts_with(b"FLYSV003")||bytes[72]!=stage.pool||amount(bytes,73)?!=stage.budget.0||p::hex(&bytes[40..72])!=config["policyHash"]||amount(bytes,89)?!=stage.deadline{return Err("INVALID_INPUT: immutable stage binding".into());}
   let pending=book.slots.values().filter(|s|s.stage==*key&&!s.accepted&&!s.released).collect::<Vec<_>>();let atoms=pending.iter().try_fold(0u64,|n,s|n.checked_add(s.amount.0)).ok_or("stage amount overflow")?;
   if amount(bytes,81)?!=stage.remaining.0||bytes[97]!=u8::from(stage.closed)||amount(bytes,98)?!=pending.len() as u64||amount(bytes,106)?!=atoms{reasons.push(format!("stage {key}: projection/reservation mismatch at observed waterline"));}
  }
  for(key,slot)in &book.slots{if slot.genesis_hash.is_empty()||slot.slot_pda.is_empty(){reasons.push("legacy unbound slot requires audited identity migration".into());continue;}let bytes=get(&slot.slot_pda,&slot.program_id,Some(b"FLYRV002"))?;if bytes.len()!=512||bytes[8..40]!=p::unhex(&slot.economic_task)?||bytes[40..72]!=p::unhex(&slot.unit_id)?||bytes[72..104]!=key_bytes(&slot.stage)?||bytes[104]!=match slot.kind.as_str(){"discovery"=>0,"coverage"=>1,"verification"=>2,"readout"=>3,"community"=>4,_=>255}||bytes[106..138]!=key_bytes(&slot.beneficiary)?||amount(bytes,170)?!=slot.amount.0{return Err("INVALID_INPUT: immutable slot/beneficiary binding".into());}if amount(bytes,178)?!=slot.paid.0||bytes[186]!=u8::from(slot.accepted)||bytes[187]!=u8::from(slot.released){reasons.push(format!("slot {key}: local payment projection pending or divergent"));}}
  let matched=local&&reasons.is_empty();let result=json!({"localLedgerReconciled":local,"chainStateReconciled":matched,"scientificVerification":"separate authorized evidence/replay","status":if matched{"reconciled"}else{status},"reasons":reasons,"bookRoot":book_root,"contextSlots":contexts,"commitment":"finalized","genesisHash":config["genesisHash"],"programId":config["programId"],"asset":asset,"observedAt":observed,"scope":"two admitted observers attest actual batch bytes and discovery waterline; no arbitrary historical slot lookup"});
  let root=id("chain-reconciliation-observation-v1",&value(r))?;sql(db.execute("INSERT OR IGNORE INTO chain_reconciliations VALUES(?,?,?,?)",params![root,asset,json!({"result":result,"signedEnvelope":r}).to_string(),at]))?;Ok(result)
 }
}
async fn reconcile(State(a):State<Arc<Authority>>,Json(r):Json<SignedRequest>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.reconcile_chain_observation(&r,now())).await.map(Json)}
pub(super) fn routes()->Router<Arc<Authority>>{Router::new().route("/api/economy/reconcile-chain",post(reconcile))}
