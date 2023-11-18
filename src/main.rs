use clap::Parser;
use std::net::SocketAddr;
mod adcache;
mod constants;
mod parser;
mod response_writer;
mod serializer;

// TODO use tokio crate

// TODO - use &str instead of String.
// Skipping for now to avoid lifetime checks
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// String form of loopback address (IPv4 or IPv6)
    #[arg(long, default_value_t = String::from("127.0.0.1:53"))]
    listener_addr: String,

    /// String form of server address (IPv4 or IPv6)
    #[arg(long, default_value_t = String::from("0.0.0.0:23"))]
    server_addr: String,

    /// String form of upstream DNS resolver address (IPv4 or IPv6)
    #[arg(long, default_value_t = String::from("1.1.1.1:53"))]
    forward_addr: String,
}

fn main() {
    let args = Args::parse();
    println!("Printing out args: {:?}", args);

    let listening_address: SocketAddr = args
        .listener_addr
        .as_str()
        .parse()
        .expect("failed to parse listening address");
    let server_address: SocketAddr = args
        .server_addr
        .as_str()
        .parse()
        .expect("failed to parse server address");
    let fwd_address: SocketAddr = args
        .forward_addr
        .as_str()
        .parse()
        .expect("failed to parse forwarding address");

    let server = adcache::server(
        listening_address,
        server_address,
        fwd_address,
        // Serve ads 99% of the time
        /*ad_rate=*/ 99,
    );
    adcache::run_server(server);
    println!("Server terminated");
}
