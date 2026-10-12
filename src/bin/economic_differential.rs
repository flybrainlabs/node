//! Replays an actual isolated SBF instruction trace through the off-chain Book.
use flypow_economic_core::{Book,Stage,Slot,Atoms,POOLS};use serde_json::{Value,json};use std::{env,fs};
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<_>=env::args().collect();if args.len()!=3{return Err("usage: economic_differential ISOLATED_TRACE REPORT".into());}
 let v:Value=serde_json::from_slice(&fs::read(&args[1])?)?;if v["environment"]!="isolated-loopback-bank"||v["formalFunds"]!=false{return Err("explicit isolated trace required".into());}
 let mut book=Book::new(format!("solana:{}:{}:8",v["genesisHash"].as_str().unwrap(),v["mint"].as_str().unwrap()),POOLS);let mut applied=0;
 for action in v["trace"].as_array().ok_or("trace")? {
  let bytes=flypow_target_protocol::unhex(action["dataHex"].as_str().ok_or("bytes")?)?;let accounts=action["accounts"].as_array().ok_or("accounts")?;let account=|i:usize|accounts[i].as_str().unwrap();
  let u64_at=|at:usize|u64::from_le_bytes(bytes[at..at+8].try_into().unwrap());let hex_at=|at:usize|flypow_target_protocol::hex(&bytes[at..at+32]);
  match bytes[0]{
   0|1=>{},
   2=>{let pool=bytes[33];let amount=u64_at(34);book.atomic(|b|b.open_stage(account(1).into(),Stage{policy:v["policyHash"].as_str().unwrap().into(),asset:b.asset.clone(),pool,budget:Atoms(amount),remaining:Atoms(amount),refund_remaining:Atoms(0),deadline:u64_at(42),closed:false,refund_recipient:"global-pool".into()}))?;},
   3=>{let kind=match bytes[65]{0=>"discovery",1=>"coverage",2=>"verification",3=>"readout",4=>"community",_=>return Err("kind".into())};book.atomic(|b|b.reserve_slot(account(2).into(),Slot{genesis_hash:v["genesisHash"].as_str().unwrap().into(),program_id:v["programId"].as_str().unwrap().into(),economic_task:hex_at(1),unit_id:hex_at(33),slot_pda:account(2).into(),stage:account(1).into(),kind:kind.into(),beneficiary:hex_at(66),amount:Atoms(u64_at(130)),contribution:format!("opaque-authorized-contract:{}",account(2)),accepted:false,released:false,paid:Atoms(0),inflight:Atoms(0)}))?;},
   4=>{let c=book.slots[account(2)].contribution.clone();book.atomic(|b|b.accept(account(2),&c))?;},
   5=>{let id=hex_at(1);let amount=u64_at(33);let key=book.payment_key_for_slot(account(2),&id)?;if let Some(p)=book.payments.get(&key){if p.amount.0!=amount||p.status!="paid"{return Err("repeated consumption mismatch".into());}}else{let beneficiary=book.slots[account(2)].beneficiary.clone();let asset=book.asset.clone();book.atomic(|b|{b.begin_payment(id.clone(),account(2),&beneficiary,&asset,amount,action["signature"].as_str().unwrap().into())?;b.resolve_payment(account(2),&id,true,false)})?;}},
   6=>book.atomic(|b|b.release_unaccepted(account(2)))?,7=>{book.atomic(|b|b.close_stage(account(1)))?;},_=>return Err("trace unsupported instruction".into())
  }applied+=1;
 }
 book.reconcile()?;
 for stage in v["finalStages"].as_array().unwrap(){let s=&book.stages[stage["address"].as_str().unwrap()];if s.remaining.0.to_string()!=stage["remainingAtoms"]||s.closed!=stage["closed"]{return Err("stage differential mismatch".into());}}
 for slot in v["finalSlots"].as_array().unwrap(){let s=&book.slots[slot["address"].as_str().unwrap()];if s.amount.0.to_string()!=slot["amountAtoms"]||s.paid.0.to_string()!=slot["paidAtoms"]||s.accepted!=slot["accepted"]||s.released!=slot["released"]{return Err("slot differential mismatch".into());}}
 for i in 0..3{if book.vaults[i].balance.0.to_string()!=v["poolBalances"][i]||book.vaults[i].free()?.to_string()!=v["globalAvailable"][i]{return Err("pool differential mismatch".into());}}
 let report=json!({"passed":true,"actualSbfActions":applied,"stages":book.stages.len(),"slots":book.slots.len(),"payments":book.payments.len(),"poolBalancesMatch":true,"globalAvailableMatches":true,"allRightsMatch":true,"environment":"isolated actual SBF trace vs Rust Book; opaque contract evidence is not scientific replay","formalFunds":false});fs::write(&args[2],serde_json::to_string_pretty(&report)?)?;println!("{report}");Ok(())
}
