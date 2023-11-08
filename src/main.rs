use std::net::UdpSocket;
use std::time::Duration;
use std::io;
use std::net::SocketAddr;
mod parser;

// checks if a query shouldn't be served - within special conditions (AXFR, DNSSEC)
// should pass the entire buffer, including the beginning
// TODO(cleanup this awkward ++ code)
fn check_query_eligibility(buf: &[u8]) -> Result<(), &'static str> {
    let mut pointer: usize = 0;
    pointer += 4; // Skip over the first 4 bytes of the header
    let qdcount: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());
    pointer += 2;
    let _adcount: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());
    pointer += 2;
    let _nscount: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());
    pointer += 2;
    let arcount: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());
    pointer += 2;
    println!("QD: {}, AD: {}, NS:{}, AR:{}", qdcount, _adcount, _nscount, arcount);

    if qdcount < 1 {
        return Err("Your query needs a question");
    }

    // Iterate over Question
    parser::skip_domain_name(&buf, &mut pointer);
    println!("printing out poitner {}", pointer);
    let query_type: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());
    println!("PRINTING OUT THE QUERY_TYPE {}", query_type);
    if query_type == 251 || query_type == 252 {
        return Err("AXFR Queries are Premium Only");
    }
    pointer += 2;
    // Consider deleting this assignment just increment the pointer by + 2
    let q_class: u16 = u16::from_be_bytes(buf[pointer..(pointer + 2)].try_into().unwrap());;
    if q_class != 1 {
        println!("Got a QCLASS that is not Internet!");
        return Err("Only internet queries are allowed");
    }
    pointer += 2;

    // EDNS Parsing
    if arcount > 0 {        
        println!("Question pointer offset = {}", pointer);
        let do_bit: bool = parser::parse_dnssec_bit(&buf[pointer..]);
        println!("DNSSEC DO BIT?: {}", do_bit);
        if do_bit {
            return Err("DNSSEC is only available in the premium + subscription"); 
        }
    }

    return Ok(());
}

// TODO(write a function that overwrites the buffer with the details you want)
// fn make_error_response() -> bool {
    // return true;
// }

fn forward_to_somewhere_else(fwd_socket: &UdpSocket,
    buf: &[u8],
    upstream_socket: &UdpSocket,
    send_to_address: &SocketAddr) -> Result<(), std::io::Error> {
    match fwd_socket.send(buf) {
        Ok(n) => println!("SUCCESFULLY SENT TO REMOTE: {}", n),
        Err(e) => return Err(e),
    }
    let mut response_buffer = [0; 512];
    match fwd_socket.recv(&mut response_buffer) {
        Ok(n) => {
            println!("RECEIVED {} BYTES!!!!", n);
            println!("PRINTING OUT THE BYTES RECEIVED {:?}", &response_buffer[0..n]);
            upstream_socket.send_to(&response_buffer[0..n], send_to_address).expect("Expecting succeed to succeed");
        }
        // Need to return servfail in this case
        Err(e) => println!("FAILED TO RECEIEVE ANYTHING {}", e),
    }
    return Ok(());
}

fn main() {
    let forwarding_socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    forwarding_socket.set_broadcast(true).expect("couldn't broadcast connection");
    let _ = forwarding_socket.set_read_timeout(Some(Duration::from_secs(10)));
    let fwd_connect_result = forwarding_socket.connect("8.8.8.8:53");
    match fwd_connect_result {
        std::result::Result::Ok(_) => println!("CONNECTED!"),
        std::result::Result::Err(a) => println!("FAILED! {}", a),
    };


    println!("Hello, world!");
    let upstream_socket = UdpSocket::bind("127.12.2.1:53").expect("couldn't bind to address");
    upstream_socket.set_nonblocking(false).expect("Failed to enter non-blocking mode");
    upstream_socket.set_broadcast(true).expect("Couldn't broadcast connection");

    let mut buf = [0; 4096];
    loop {
        match upstream_socket.recv_from(&mut buf) {
            Ok(n) => {
                println!("received {} bytes from {}", n.0, n.1);
                println!("the bytes we received {:?}", &buf[0..n.0]);
                match check_query_eligibility(&buf) {
                    Ok(_) => println!("PASSED CHECKS"),
                    Err(errstring) => println!("YOU GOT SOME ERROR {}", errstring),
                }
                println!("done checking elligibility");
                let parsed_header = parser::deserialize(&buf[0..12]).expect("Couldn't parse the header correctly");
                println!("Parsed Header: {:?}", parsed_header);
                if parsed_header.arcount > 0 {
                    let pointer: usize = parser::parse_over_question(&buf[12..]);
                    println!("Question pointer offset = {}", pointer);
                    let do_bit: bool = parser::parse_dnssec_bit(&buf[(12 + pointer)..]);
                    println!("DNSSEC DO BIT?: {}", do_bit);
                }

                match forward_to_somewhere_else(&forwarding_socket, &buf[0..n.0], &upstream_socket, &n.1) {
                    Ok(_) => println!("successfully forwarded response"),
                    Err(e) => println!("failed to forward response: {}", e),
                }
                buf = [0; 4096]; // Need to reset the buffer
            }
            Err(ref e) if e.kind() != io::ErrorKind::WouldBlock => {
                println!("AOISDJOAISJD");
            }
            Err(_e) => {}
        }
    };
}
