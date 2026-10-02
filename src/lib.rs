//! nnlan: authenticated UDP, decentralized control plane and Linux TUN daemon.
//! Subnet/exit kernel integration and full performance acceptance remain in development.
//! Control-plane models accept verified inputs; they are not wire decoders.

#[cfg(not(target_os = "linux"))]
compile_error!("The first nnlan implementation targets Linux.");

pub mod address;
pub mod config;
pub mod identity;
pub mod peers;
pub mod plan;
pub mod protocol;
pub mod reliability;
pub mod routing;
pub mod transport;
pub mod trust;

pub mod doctor;
pub mod runtime;
pub mod ui;
