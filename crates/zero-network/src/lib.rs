pub mod gossip;
pub mod server;

pub mod proto {
    tonic::include_proto!("zero");
}
