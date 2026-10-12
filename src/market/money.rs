//! Canonical atom parsing and cumulative allocation. No floating point funds.
pub fn atoms(s:&str)->super::Result<u128> {flypow_service_core::atoms(s).map_err(String::from)}
pub fn add(a:u128,b:u128)->super::Result<u128> {flypow_service_core::add(a,b).map_err(String::from)}
pub fn sub(a:u128,b:u128)->super::Result<u128> {flypow_service_core::sub(a,b).map_err(String::from)}
pub fn proportional(a:u128,b:u64,c:u64)->super::Result<u128> {flypow_service_core::proportional(a,b,c).map_err(String::from)}
pub fn pools(a:u128,b:[u16;4])->super::Result<([u128;4],u128)> {flypow_service_core::pools(a,b).map_err(String::from)}
