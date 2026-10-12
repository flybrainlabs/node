//! Receipt-authorized delivery. These fields and file paths never enter Explorer.
use super::*;
use axum::body::Body;
use tokio::io::AsyncReadExt;
impl Authority{
    pub(super) fn freeze_delivery_tx(&self,tx:&Connection,sid:&str,readout:&str,contribution:&str,manifest:&Value,at:u64)->Result<()> {
        if manifest["schema"]!="flybrain-private-delivery-v1"||manifest["readoutId"]!=readout||manifest["contributionId"]!=contribution||manifest["license"].as_str().is_none_or(|s|s.is_empty()||s.len()>1024){return Err("INVALID_INPUT: frozen delivery bindings/license".into());}
        let acceptance=text(manifest,"acceptanceId")?;root(&acceptance)?;
        if sql(tx.query_row("SELECT COUNT(*) FROM science_acceptances WHERE id=? AND contribution_id=?",params![acceptance,contribution],|r|r.get::<_,u64>(0)))?!=1{return Err("AUTHORIZATION: delivery acceptance").map_err(String::from);}
        let list=manifest["files"].as_array().ok_or("INVALID_INPUT: delivery files")?;if list.is_empty()||list.len()>32{return Err("INVALID_INPUT: delivery file bound".into());}
        let base=self.data.join("private/deliveries").join(sid);let mut names=std::collections::BTreeSet::new();
        for f in list {let name=text(f,"name")?;if name.len()>80||name.starts_with('.')||!name.bytes().all(|b|b.is_ascii_alphanumeric()||b"-_.".contains(&b))||!names.insert(name.clone()){return Err("INVALID_INPUT: delivery name".into());}
            let path=base.join(&name);let meta=fs::symlink_metadata(&path).map_err(|_|"NOT_FOUND: delivery file")?;if !meta.is_file()||meta.file_type().is_symlink()||meta.len()>512*1024*1024{return Err("AUTHORIZATION: private file layout/size".into());}
            if product::digest_file(&path)?!=(text(f,"sha256")?,num(f,"bytes")?){return Err("DAMAGED_ARTIFACT: actual delivery file hash".into());}
        }
        let root=id("private-delivery-manifest-v1",manifest)?;let signature=self.sign("private-delivery-manifest-v1",manifest)?;
        sql(tx.execute("INSERT INTO private_deliveries VALUES(?,?,?,?,?)",params![sid,manifest.to_string(),root,signature,at]))?;
        sql(tx.execute("INSERT INTO private_delivery_events(request_id,kind,manifest_root,created_at) VALUES(?,'delivered',?,?)",params![sid,root,at]))?;Ok(())
    }
    pub fn delivery_action(&self,v:&Value,at:u64)->Result<Value>{
        self.service_lookup(v)?;let sid=text(v,"ticketId")?;let action=text(v,"action")?;
        if !["received","accepted","approve-publication"].contains(&action.as_str()){return Err("INVALID_INPUT: delivery action".into());}
        let mut db=self.lock()?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let root:String=sql(tx.query_row("SELECT manifest_root FROM private_deliveries WHERE request_id=?",[&sid],|r|r.get(0)))?;
        if v["manifestRoot"]!=root{return Err("CONFLICT: frozen delivery root".into());}
        let existing:u64=sql(tx.query_row("SELECT COUNT(*) FROM private_delivery_events WHERE request_id=? AND kind=? AND manifest_root=?",params![sid,action,root],|r|r.get(0)))?;
        if existing==0{sql(tx.execute("INSERT INTO private_delivery_events(request_id,kind,manifest_root,created_at) VALUES(?,?,?,?)",params![sid,action,root,at]))?;}
        let consent=id("customer-publication-consent-v1",&json!({"requestId":sid,"manifestRoot":root,"scope":"versioned-public-scientific-package-only"}))?;
        sql(tx.commit())?;Ok(json!({"ticketId":sid,"action":action,"manifestRoot":root,"customerConsentId":if action=="approve-publication"{Some(consent)}else{None},"incomeRecognized":false}))
    }
    fn private_delivery_file(&self,v:&Value)->Result<(PathBuf,u64,String)>{
        self.service_lookup(v)?;let sid=text(v,"ticketId")?;let name=text(v,"name")?;let db=self.lock()?;let manifest:Value=parse(sql(db.query_row("SELECT manifest FROM private_deliveries WHERE request_id=?",[&sid],|r|r.get(0)))?)?;
        let file=manifest["files"].as_array().ok_or("delivery files")?.iter().find(|f|f["name"]==name).ok_or("NOT_FOUND: delivery file")?;
        let path=self.data.join("private/deliveries").join(&sid).join(&name);let size=num(file,"bytes")?;let sha=text(file,"sha256")?;drop(db);if product::digest_file(&path)?!=(sha.clone(),size){return Err("DAMAGED_ARTIFACT: delivery changed".into());}Ok((path,size,sha))
    }
}
async fn action(State(a):State<Arc<Authority>>,Json(v):Json<Value>)->std::result::Result<Json<Value>,ApiError>{blocking(a,move|a|a.delivery_action(&v,now())).await.map(Json)}
async fn file(State(a):State<Arc<Authority>>,Json(v):Json<Value>)->std::result::Result<Response,ApiError>{
    let(path,size,sha)=blocking(a,move|a|a.private_delivery_file(&v)).await?;
    let file=tokio::fs::File::open(path).await.map_err(|_|ApiError("NOT_FOUND: delivery file".into()))?;
    let stream=futures_util::stream::try_unfold((file,size),|(mut f,left)|async move{if left==0{return Ok::<_,std::io::Error>(None);}let mut b=vec![0;left.min(65536) as usize];let n=f.read(&mut b).await?;if n==0{return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof,"delivery truncated"));}b.truncate(n);Ok(Some((Bytes::from(b),(f,left-n as u64))))});
    Ok(([("content-type","application/octet-stream"),("cache-control","private, no-store"),("x-content-type-options","nosniff"),("x-content-sha256",sha.as_str())],Body::from_stream(stream)).into_response())
}
pub(super) fn routes()->Router<Arc<Authority>>{Router::new().route("/api/service-requests/delivery-action",post(action)).route("/api/service-requests/delivery-file",post(file))}
