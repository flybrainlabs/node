//! Loopback V2 development service. Secrets are created privately, not printed.
use std::{env,fs,path::PathBuf};
use flypow::target_authority::{Authority,AuthorityConfig,router,now};
#[tokio::main]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    let args:Vec<_>=env::args().collect();if args.len()<3||args.len()>4{return Err("usage: target_authority CONFIG.json DATA_DIR [127.0.0.1:8787]".into());}
    let config:AuthorityConfig=serde_json::from_slice(&fs::read(&args[1])?)?;let a=Authority::open(PathBuf::from(&args[2]),config)?;a.use_wall_clock();a.maintain(now())?;a.project_explorer()?;
    let address=args.get(3).map(String::as_str).unwrap_or("127.0.0.1:8787");let listener=tokio::net::TcpListener::bind(address).await?;
    println!("V2 development authority listening on http://{address}; authorityId={}; no payment/rewards; one trusted authority",a.authority_id);
    let maintenance=a.clone();tokio::spawn(async move{let mut interval=tokio::time::interval(std::time::Duration::from_secs(1));loop{interval.tick().await;let a=maintenance.clone();let result=tokio::task::spawn_blocking(move||a.maintain(now())).await;if let Ok(Err(e))=result{eprintln!("V2 maintenance: {e}");}}});
    let projector=a.clone();tokio::spawn(async move{let mut interval=tokio::time::interval(std::time::Duration::from_secs(2));let mut cursor=0u64;loop{interval.tick().await;let copy=projector.clone();let result=tokio::task::spawn_blocking(move||{let v=copy.events(cursor)?;copy.project_explorer()?;Ok::<_,String>(v)}).await;match result{Ok(Ok(v))=>{for e in v["events"].as_array().unwrap(){projector.broadcast_event(e.clone());}cursor=v["nextCursor"].as_u64().unwrap_or(cursor);},_=>eprintln!("Explorer projection delayed; retained source outbox")}}});
    let archive=a.clone();tokio::spawn(async move{let mut interval=tokio::time::interval(std::time::Duration::from_secs(60));loop{interval.tick().await;let copy=archive.clone();let _=tokio::task::spawn_blocking(move||copy.archive_housekeeping(now())).await;}});
    let housekeeping=a.clone();tokio::spawn(async move{let mut interval=tokio::time::interval(std::time::Duration::from_secs(3600));loop{interval.tick().await;let a=housekeeping.clone();let result=tokio::task::spawn_blocking(move||{a.product_housekeeping(now())?;a.audit_public_objects()?;let report=a.economic_reconcile()?;if report["status"]=="requires-reconciliation"{return Err("economic reconciliation discrepancy".to_string());}Ok::<_,String>(())}).await;if let Ok(Err(e))=result{eprintln!("Product housekeeping: {e}");}}});
    axum::serve(listener,router(a).into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;Ok(())
}
