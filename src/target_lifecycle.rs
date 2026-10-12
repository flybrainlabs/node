//! Bounded background maintenance. No visitor read advances protocol state.
use super::*;
impl Authority {
    pub(super) fn expire_history_tx(&self,tx:&Connection,at:u64)->Result<()> {
        let mut q=sql(tx.prepare("SELECT claim_id,round_id,status FROM candidate_claims WHERE (status='COMMITTED' AND reveal_deadline<?) OR (status='REVEALED' AND verification_deadline<?) ORDER BY MIN(reveal_deadline,verification_deadline),claim_id LIMIT 128"))?;
        let rows=sql(q.query_map(params![at,at],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;drop(q);
        for (cid,rid,status) in rows {
            let reason=if status=="COMMITTED"{"reveal-deadline-expired"}else{"verification-deadline-expired"};
            sql(tx.execute("UPDATE candidate_claims SET status='TIMED_OUT' WHERE claim_id=?",[&cid]))?;
            sql(tx.execute("INSERT OR IGNORE INTO candidate_terminal VALUES(?,?,?)",params![cid,reason,at]))?;
            sql(tx.execute("UPDATE verification_jobs SET status='EXPIRED' WHERE claim_id=? AND status IN ('PENDING','LEASED')",[&cid]))?;
            self.event(tx,Some(&rid),"CANDIDATE_TERMINAL",json!({"claimId":cid,"status":"TIMED_OUT","reason":reason}),at)?;
        }Ok(())
    }
    pub fn archive_housekeeping(&self,at:u64)->Result<Value> {
        // Holding the source writer lock serializes with upload/seal/vote. It
        // only deletes redundant sealed chunks or expired incomplete uploads.
        let db=self.lock()?;
        let mut stmt=sql(db.prepare("SELECT a.upload_id,a.status,c.status,c.verification_deadline,EXISTS(SELECT 1 FROM round_winners w WHERE w.claim_id=c.claim_id),EXISTS(SELECT 1 FROM verification_jobs j WHERE j.claim_id=c.claim_id AND j.status='LEASED' AND j.lease_until>=?) FROM candidate_artifacts a JOIN candidate_claims c USING(claim_id)"))?;
        let rows=sql(stmt.query_map([at],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,u64>(3)?,r.get::<_,bool>(4)?,r.get::<_,bool>(5)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;drop(stmt);
        let mut physical=0u64;let mut temporary=0u64;let mut freed=0u64;
        for (uid,status,claim,deadline,winner,leased) in rows {
            let dir=self.upload_dir(&uid)?;let sealed=dir.join("response.bin");
            if status=="SEALED"&&!sealed.is_file(){
                let(expected,sha):(u64,String)=sql(db.query_row("SELECT bytes,sha256 FROM candidate_artifacts WHERE upload_id=?",[&uid],|r|Ok((r.get(0)?,r.get(1)?))))?;
                let mut q=sql(db.prepare("SELECT chunk_index,bytes,sha256 FROM artifact_chunks WHERE upload_id=? ORDER BY chunk_index"))?;let chunks=sql(q.query_map([&uid],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?,r.get::<_,String>(2)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;drop(q);
                if chunks.len() as u64!=expected.div_ceil(CHUNK as u64){return Err("DAMAGED_ARTIFACT: sealed source unavailable; restore preserved backup".into());}
                let tmp=dir.join(format!("recovery-{}.partial",random_suffix()?));let mut f=fs::OpenOptions::new().create_new(true).write(true).open(&tmp).map_err(|e|e.to_string())?;let mut h=Sha256::new();let mut total=0;
                for(i,(index,size,digest))in chunks.into_iter().enumerate(){if index!=i as u64{return Err("DAMAGED_ARTIFACT: recovery chunk order".into());}let bytes=fs::read(dir.join(format!("chunk-{index}.bin"))).map_err(|_|"DAMAGED_ARTIFACT: sealed archive recovery source")?;if bytes.len() as u64!=size||hash(&bytes)!=digest{return Err("DAMAGED_ARTIFACT: recovery chunk digest".into());}h.update(&bytes);f.write_all(&bytes).map_err(|e|e.to_string())?;total+=size;}
                if total!=expected||p::hex(&h.finalize())!=sha{return Err("DAMAGED_ARTIFACT: recovery response digest".into());}f.sync_all().map_err(|e|e.to_string())?;fs::rename(tmp,&sealed).map_err(|e|e.to_string())?;sync_dir(&dir)?;
            }
            let can_clear_partial=status=="UPLOADING" && ["INVALID","TIMED_OUT"].contains(&claim.as_str()) && at>deadline.saturating_add(7*86400) && !winner && !leased;
            let cleanup=status=="SEALED" && sealed.is_file() || can_clear_partial;
            if cleanup {sql(db.execute("INSERT INTO artifact_lifecycle(upload_id,lifecycle,checked_at,cleanup_started_at) VALUES(?,'cleaning',?,?) ON CONFLICT(upload_id) DO UPDATE SET lifecycle='cleaning',cleanup_started_at=excluded.cleanup_started_at",params![uid,at,at]))?;}
            let mut size=0u64;let mut temp=0u64;
            if dir.is_dir() {for entry in fs::read_dir(&dir).map_err(|e|e.to_string())? {
                let entry=entry.map_err(|e|e.to_string())?;let meta=fs::symlink_metadata(entry.path()).map_err(|e|e.to_string())?;if !meta.is_file(){continue;}
                let name=entry.file_name().to_string_lossy().into_owned();let is_temp=name.starts_with("chunk-") || name.ends_with(".partial");
                if cleanup && (is_temp || can_clear_partial&&name=="response.bin") {fs::remove_file(entry.path()).map_err(|e|e.to_string())?;freed=freed.saturating_add(meta.len());continue;}
                size=size.saturating_add(meta.len());if is_temp{temp=temp.saturating_add(meta.len());}
            }}
            if can_clear_partial {sql(db.execute("UPDATE candidate_artifacts SET status='CLEANED' WHERE upload_id=? AND status='UPLOADING'",[&uid]))?;}
            sql(db.execute("INSERT INTO artifact_lifecycle(upload_id,lifecycle,physical_bytes,temp_bytes,checked_at,cleaned_at) VALUES(?,?,?,?,?,?) ON CONFLICT(upload_id) DO UPDATE SET lifecycle=excluded.lifecycle,physical_bytes=excluded.physical_bytes,temp_bytes=excluded.temp_bytes,checked_at=excluded.checked_at,cleaned_at=excluded.cleaned_at",params![uid,if can_clear_partial{"cleaned"}else if status=="SEALED"{"evidence-retained"}else{"uploading"},size,temp,at,if cleanup{Some(at)}else{None}]))?;
            physical=physical.saturating_add(size);temporary=temporary.saturating_add(temp);
        }
        Ok(json!({"physicalBytes":physical.to_string(),"temporaryBytes":temporary.to_string(),"freedRedundantBytes":freed.to_string(),"winnerEvidence":"retained","partialRetentionSeconds":7*86400}))
    }
}
