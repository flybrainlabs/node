//! Public immutable objects are deduplicated only inside the public permission
//! domain. Existing result URLs remain hard links, with cached trusted digests.
use super::*;
use std::time::UNIX_EPOCH;
fn stamp(path:&std::path::Path)->Result<(u64,String,String)>{
    let m=fs::symlink_metadata(path).map_err(|_|"DAMAGED_ARTIFACT: public object missing")?;
    if !m.is_file()||m.file_type().is_symlink(){return Err("AUTHORIZATION: public object layout".into());}
    #[cfg(unix)]let inode={use std::os::unix::fs::MetadataExt;m.ino().to_string()};
    #[cfg(not(unix))]let inode=String::new();
    Ok((m.len(),m.modified().map_err(|_|"file metadata")?.duration_since(UNIX_EPOCH).map_err(|_|"file time")?.as_nanos().to_string(),inode))
}
impl Authority{
    pub(super) fn install_public_object(&self,source:&std::path::Path,destination:&std::path::Path,sha:&str,bytes:u64)->Result<()> {
        root(sha)?;let objects=self.data.join("public-objects");fs::create_dir_all(&objects).map_err(|e|e.to_string())?;
        let object=objects.join(sha);
        if object.exists(){if self.cached_public_digest(&object,sha,bytes).is_err(){if product::digest_file(&object)?!=(sha.into(),bytes){return Err("DAMAGED_ARTIFACT: existing public object".into());}}}
        else {let tmp=objects.join(format!("{sha}-{}.partial",random_suffix()?));fs::copy(source,&tmp).map_err(|e|e.to_string())?;if product::digest_file(&tmp)?!=(sha.into(),bytes){return Err("DAMAGED_ARTIFACT: public object copy".into());}fs::File::open(&tmp).and_then(|f|f.sync_all()).map_err(|e|e.to_string())?;fs::rename(&tmp,&object).map_err(|e|e.to_string())?;}
        let tmp=destination.with_extension(format!("public-link-{}",random_suffix()?));fs::hard_link(&object,&tmp).map_err(|e|e.to_string())?;fs::rename(&tmp,destination).map_err(|e|e.to_string())?;
        let(size,mtime,inode)=stamp(&object)?;let db=self.lock()?;
        sql(db.execute("INSERT INTO public_objects VALUES(?,?,?,?,?,'trusted') ON CONFLICT(sha256) DO UPDATE SET checked_at=excluded.checked_at,mtime_ns=excluded.mtime_ns,inode=excluded.inode,status='trusted'",params![sha,size,now(),mtime,inode]))?;Ok(())
    }
    pub(super) fn cached_public_digest(&self,path:&std::path::Path,sha:&str,bytes:u64)->Result<()> {
        let(size,mtime,inode)=stamp(path)?;let db=self.lock()?;let saved:Option<(u64,String,String,String)>=sql(db.query_row("SELECT bytes,mtime_ns,inode,status FROM public_objects WHERE sha256=?",[sha],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional())?;
        if saved!=Some((bytes,mtime,inode,"trusted".into()))||size!=bytes{return Err("DAMAGED_ARTIFACT: public object metadata changed; background digest check required".into());}Ok(())
    }
    pub fn migrate_public_objects(&self)->Result<Value>{
        let rows={let db=self.lock()?;let mut q=sql(db.prepare("SELECT result_id,name,sha256,bytes FROM public_result_files ORDER BY result_id,name"))?;let rows=sql(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,u64>(3)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        let mut count=0;for(rid,name,sha,bytes)in rows{let path=self.data.join("public-results").join(&rid).join(&name);if self.cached_public_digest(&path,&sha,bytes).is_err(){if product::digest_file(&path)?!=(sha.clone(),bytes){return Err("DAMAGED_ARTIFACT: historical public file".into());}self.install_public_object(&path,&path,&sha,bytes)?;count+=1;}}
        Ok(json!({"deduplicatedLinks":count,"scope":"public objects only; private artifacts untouched"}))
    }
    pub fn audit_public_objects(&self)->Result<()> {
        let rows={let db=self.lock()?;let mut q=sql(db.prepare("SELECT sha256,bytes FROM public_objects ORDER BY sha256"))?;let rows=sql(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        for(sha,bytes)in rows {let path=self.data.join("public-objects").join(&sha);let matches=product::digest_file(&path).is_ok_and(|v|v==(sha.clone(),bytes));let (_,mtime,inode)=stamp(&path)?;let db=self.lock()?;sql(db.execute("UPDATE public_objects SET checked_at=?,mtime_ns=?,inode=?,status=? WHERE sha256=?",params![now(),mtime,inode,if matches{"trusted"}else{"damaged"},sha]))?;}Ok(())
    }
    pub(super) fn index_result_neurons_tx(db:&Connection,rid:&str,g:&GoalSpec,input:&p::CandidateInput)->Result<()> {
        sql(db.execute("INSERT OR IGNORE INTO result_neurons VALUES(?,?,'stimulus')",params![rid,input.stimulated_body_id]))?;
        for (role,set) in [("target",&g.response_set),("off-target",&g.off_target_set)] {for neuron in set{sql(db.execute("INSERT OR IGNORE INTO result_neurons VALUES(?,?,?)",params![rid,neuron.body_id,role]))?;sql(db.execute("INSERT OR IGNORE INTO result_neurons VALUES(?,?,'report-reference')",params![rid,neuron.body_id]))?;}}Ok(())
    }
}
fn public_body_map(path:&std::path::Path,g:&GoalSpec)->Result<Vec<u64>>{
    use std::io::Read;let mut f=fs::File::open(path).map_err(|_|"NOT_FOUND: public graph")?;let mut header=[0u8;52];f.read_exact(&mut header).map_err(|_|"DAMAGED_ARTIFACT: graph header")?;
    if &header[..8]!=b"FBGR1\0\0\0"||u32::from_le_bytes(header[8..12].try_into().unwrap())!=g.neuron_count||p::hex(&header[20..52])!=g.registry_root{return Err("DAMAGED_ARTIFACT: body registry identity".into());}
    let mut raw=vec![0u8;g.neuron_count as usize*8];f.read_exact(&mut raw).map_err(|_|"DAMAGED_ARTIFACT: body map")?;let bodies=raw.chunks_exact(8).map(|c|u64::from_le_bytes(c.try_into().unwrap())).collect::<Vec<_>>();if bodies.windows(2).any(|p|p[0]>=p[1]){return Err("DAMAGED_ARTIFACT: body map order".into());}Ok(bodies)
}
impl Authority{
    pub fn backfill_public_response_roles(&self)->Result<()> {
        let records={let db=self.lock()?;let mut q=sql(db.prepare("SELECT p.id,p.task_id,p.summary FROM public_results p LEFT JOIN result_response_indexes i ON i.result_id=p.id WHERE i.result_id IS NULL"))?;let rows=sql(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?))))?.collect::<rusqlite::Result<Vec<_>>>().map_err(|e|e.to_string())?;rows};
        for(rid,gid,summary)in records{let g:GoalSpec={let db=self.lock()?;serde_json::from_str(&sql(db.query_row("SELECT spec_json FROM goal_specs WHERE goal_id=?",[gid],|r|r.get::<_,String>(0)))?).map_err(|_|"goal")?};let summary=parse(summary)?;let input:p::CandidateInput=serde_json::from_value(summary["input"].clone()).map_err(|_|"input")?;let base=self.data.join("public-results").join(&rid);let bodies=public_body_map(&base.join("graph.bin"),&g)?;let mut responding=std::collections::BTreeSet::new();
            for j in 0..summary["requiredBackgrounds"].as_u64().ok_or("backgrounds")?{let bytes=fs::read(base.join(format!("trial-{j}.bin"))).map_err(|_|"NOT_FOUND: public events")?;p::evaluate(&g,&input,&bytes)?;let baseline=u32::from_le_bytes(bytes[472..476].try_into().unwrap()) as usize;for event in bytes[480..].chunks_exact(8).skip(baseline){let index=u32::from_le_bytes(event[4..].try_into().unwrap()) as usize;responding.insert(*bodies.get(index).ok_or("event body map")?);}}
            let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;for body in &responding{sql(tx.execute("INSERT OR IGNORE INTO result_neurons VALUES(?,?,'actual-response')",params![rid,body.to_string()]))?;}sql(tx.execute("INSERT OR IGNORE INTO result_response_indexes VALUES(?,?,?,?)",params![rid,g.graph_root,responding.len(),now()]))?;sql(tx.commit())?;
        }Ok(())
    }
}
