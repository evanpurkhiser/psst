pub mod browser_protocol;
pub mod dbus;
mod http;
mod passkey_authorization;
mod service;

use std::net::SocketAddr;

use crate::error::Result;
use service::Service;
use tokio::time::{Duration, MissedTickBehavior};

pub async fn run(sharing_address: SocketAddr, browser_address: SocketAddr) -> Result<()> {
    let service = Service::default();
    let _connection = dbus::serve(service.clone()).await?;
    let expiration = tokio::spawn(expire_sessions(service.clone()));
    let result = http::serve(service, sharing_address, browser_address).await;
    expiration.abort();
    result?;
    Ok(())
}

async fn expire_sessions(service: Service) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        service.expire().await;
    }
}
