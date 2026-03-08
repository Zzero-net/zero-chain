pub mod server;
pub mod gossip;

pub mod proto {
    tonic::include_proto!("zero");
}
