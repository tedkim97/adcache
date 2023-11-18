use rand::{thread_rng, Rng};
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use crate::parser;
use crate::parser::BareHeader;
use crate::response_writer;
use rand::seq::SliceRandom;

// TODO - add unit tests + cleanup reference passing (oops)

#[derive(Debug)]
pub struct AdInterceptServer {
    pub forwarding_socket: UdpSocket,
    pub udp_client_socket: UdpSocket,
    pub tcp_client_socket: TcpListener,
    pub advertisements: Vec<&'static str>,
    // The probability that an advertisement will be attached to the DNS response
    pub ad_rate: u8,
}

// Recklessly spawn a thread whenever we receive a UDP + TCP query - not ideal.
// Ideally we would use a threadpool to reduce chances of mass queries crashing
// the process, but that would involve (1) making our own threadpool or (2) pulling in
// another crate. The original goal was to have this externally dependency-less, but I
// gave up on that for a RNG crate... I also don't want to spend a ton of time engineering
// a joke...
pub fn run_server(server: &'static AdInterceptServer) {
    let udp_thread = thread::spawn(move || {
        let mut buf: Vec<u8> = vec![0; 512];
        loop {
            match server.udp_client_socket.recv_from(&mut buf) {
                Ok((size, src)) => {
                    // Socket is non blocking, so a copy is necessary (because
                    // we would be mutating the original buffer in a multi-thread way)
                    let mut copied_buffer = buf.clone();
                    thread::spawn(move || {
                        handle_udp_connection(&mut copied_buffer, size, src, &server);
                    });
                }
                Err(ref e) if e.kind() != io::ErrorKind::WouldBlock => {
                    println!("UDP blocking error occured");
                }
                Err(_e) => {}
            }
        }
    });
    let tcp_thread = thread::spawn(move || loop {
        for stream_res in server.tcp_client_socket.incoming() {
            thread::spawn(|| {
                match stream_res {
                    Ok(mut stream) => {
                        println!("received TCP connection");
                        deny_tcp_connection(&mut stream)
                    }
                    Err(ref e) if e.kind() != io::ErrorKind::WouldBlock => {
                        println!("TCP blocking error occured");
                    }
                    Err(_e) => {}
                };
            });
        }
    });
    let _ = udp_thread.join();
    let _ = tcp_thread.join();
}

pub fn server(
    listening_addr: SocketAddr,
    server_addr: SocketAddr,
    fwd_addr: SocketAddr,
    ad_rate: u8,
) -> &'static AdInterceptServer {
    static SERVER: OnceLock<AdInterceptServer> = OnceLock::new();
    SERVER.get_or_init(|| {
        // Configure UDP inbound connections
        let udp_client_socket = UdpSocket::bind(listening_addr)
            .expect("failed to open a UDP socket on the listening port");
        udp_client_socket
            .set_nonblocking(false)
            .expect("failed to configure UDP socket to nonblocking mode");
        udp_client_socket
            .set_broadcast(true)
            .expect("failed to set broadcast for socket");
        // Configure UDP outbound connections
        let forwarding_socket =
            UdpSocket::bind(server_addr).expect("failed to bind to server address");
        forwarding_socket
            .set_broadcast(true)
            .expect("failed to set broadcast for forwarding socket");
        forwarding_socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("failed to set read timeout");
        forwarding_socket
            .connect(fwd_addr)
            .expect("failed to connect forwarding socket");
        // Configure TCP listener
        let tcp_client_socket = TcpListener::bind(listening_addr)
            .expect("failed to open a TCP socket on the listeng port");
        tcp_client_socket
            .set_nonblocking(true)
            .expect("failed to configure TCP socket to non-blocking mode");

        let server = AdInterceptServer {
            forwarding_socket,
            udp_client_socket,
            tcp_client_socket,
            advertisements: vec![
                "This response is sponsored by $MEAL_DELIVERY_KIT! Use this coupon to get $2 off your next order!",
                "Watch the action-packed, romantic, comedy of the century $MOVIE in theaters near this summer",
                "Welcome to the metaverse! Come here to buy real-estate in the metaverse",
                "Lonely? I've fixed my crippling loneliness by generating an AI partner. Click here to generate your own AI partner!",
                "I make $100,000 USD every month! Buy my course to find out how!",
                "Drink $BRAND beer to trick yourself into thinking you had a good time",
                "Introducing the $HAMBURGER_WITH_STUPID_QUIRK at $BRAND fast food. only available for a limited time",
                "Brought to you by dollar shave club",
                "People think you smell if you use $BRAND shampoo - use $OTHER_BRAND shampoo instead!",
                "Existing $BRAND detergent not doing it? Why not buy $OTHER_BRAND liquid detergent! It cleans X times better",
                "BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY BUY",
                "CONSUME CONSUME CONSUME CONSUME CONSUME CONSUME CONSUME CONSUME CONSUME",
                "don't you have anything better to do?",
                "get back to work",
                "CTRL+HEART: dating over udp",
                "Too cheap to pay artists? Use our AI image generator to make art for you",
                "Need to launder some money? Invest in our cryptocurrency!",
                "CONSUME MORE PEASANT",
                "This response is sponsored by Raid Shadow Legends",
                "Meet hot, lonely DNS records in your area tonight",
            ],
            ad_rate,
        };
        server
    })
}

/// Returns a DNS response with a SERVFAIL and a TXT record saying TCP connections are for premium+ users
fn deny_tcp_connection(stream: &mut TcpStream) {
    // TODO - stack allocated vector
    // TODO - think about case for malformed TCP query, but if we're unconditionally returning refused codes,
    // I don't think it would matter
    let mut buf: Vec<u8> = vec![0; 512];
    match stream.read(&mut buf) {
        Ok(n) => {
            let mod_header = parser::parse_bare_header(&buf[2..n])
                .expect("Unable to calculate message header+offsets");

            let added_size = response_writer::make_refused_response_tcp(
                &mut buf,
                &mod_header,
                "TCP is for enterprise clients only",
            )
            .expect("could not make refused response");

            let prior_msg_size = u16::from_be_bytes(buf[0..2].try_into().unwrap());
            let u16_size: u16 = added_size.try_into().unwrap();
            [buf[0], buf[1]] = (prior_msg_size + u16_size).to_be_bytes();
            let _ = stream.write_all(&buf[0..(n + added_size)]);
        }
        Err(e) => println!("Reading from socket failed: {:?}", e),
    };
}

fn handle_udp_connection(
    mut buf: &mut Vec<u8>,
    size: usize,
    src: SocketAddr,
    server: &AdInterceptServer,
) {
    let header = parser::parse_bare_header(&buf[0..size])
        .expect("Unable to calculate message header+offsets");

    match check_query_eligibility(&buf, &header) {
        Ok(_) => match forward_packet(&server, &buf[0..size], &src) {
            Ok(_) => (),
            Err(e) => println!("failed to forward response: {}", e),
        },
        Err(errstring) => {
            // TODO: use a pattern match so we have proper error handling
            let added_bytes: usize =
                response_writer::make_error_response(&mut buf, &header, errstring).unwrap();
            // TODO - figure out why the added bytes here cause some weird offsets
            match server
                .udp_client_socket
                .send_to(&buf[0..(size + added_bytes)], &src)
            {
                Ok(sent_bytes) => println!("sent {} bytes", sent_bytes),
                Err(_) => println!("Failed to send to socket"),
            }
        }
    }
    zero_out_vector(&mut buf); // Need to reset the buffer
}

/// Function that checks if a DNS query should be served and returns a joke
/// Things that are not allowed
fn check_query_eligibility(buf: &[u8], header: &BareHeader) -> Result<(), &'static str> {
    // Jokes for Malformed Queries (probably will never happen)
    if header.qdcount < 1 {
        return Err("Your query needs a question (QDCOUNT is less than 1)");
    }

    if header.ancount > 0 || header.nscount > 0 {
        return Err("Format Error, we will bill your ISP");
    }

    // We've already parsed the 12 byte header
    let mut pointer: usize = 12;

    // Iterate over Question
    parser::skip_domain_name(&buf, &mut pointer);

    // Jokes about the QTYPE
    let query_type: u16 = parser::parse_u16(&buf, &mut pointer);
    match query_type {
        // Obsolete Record Types
        3 | 4 | 30 | 38 | 254 | 32769 => return Err("You are OLD"),
        // MX
        15 => return Err("Very brave of you to trust me with your email"),
        // AXFR/IXFR (this will never happen because these are TCP only)
        251 | 252 => return Err("XFR Queries are for premium members only!"),
        // Unassigned
        // Maybe let clients do this?
        32770..=65279 => return Err("asdaoisdj"),
        // Private Use
        // Maybe let clients make these queries this?
        65280..=65534 => return Err("asdaoisdj"),
        // Reserved
        65535 => return Err("aisudoaisdj"),
        // everything else is OK
        _ => (),
    }

    // Consider deleting this assignment just increment the pointer by + 2
    let query_class: u16 = parser::parse_u16(&buf, &mut pointer);
    // Jokes about the QCLASS
    match query_class {
        1 => (),
        3 | 4 => return Err("DN$ only supports queries made after 1990"),
        _ => (),
    }

    // EDNS Parsing
    if header.arcount > 0 {
        let do_bit: bool = parser::parse_dnssec_bit(&buf[pointer..]);
        if do_bit {
            return Err("DN$ only supports DNSSEC for customers in the ENTERPRISE tier");
        }
    }

    Ok(())
}

fn forward_packet(
    server: &AdInterceptServer,
    buf: &[u8],
    send_to_address: &SocketAddr,
) -> Result<(), std::io::Error> {
    match server.forwarding_socket.send(buf) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }
    let mut response_buffer = vec![0; 512];
    match server.forwarding_socket.recv(&mut response_buffer) {
        Ok(n) => {
            let added_size =
                insert_advertisement(&mut response_buffer, &server).expect("failed to insert ad");
            server
                .udp_client_socket
                .send_to(&response_buffer[0..(n + added_size)], send_to_address)
                .expect("Expecting succeed to succeed");
        }
        // Just drop packets if the upstream returns an error
        Err(e) => println!("Failed to get something from the upstream: {}", e),
    }
    Ok(())
}

// Randomly insert an advertisement for a customer
fn insert_advertisement(
    mut response_buffer: &mut Vec<u8>,
    server: &AdInterceptServer,
) -> Result<usize, &'static str> {
    if thread_rng().gen_range(0..100) > server.ad_rate {
        return Ok(0);
    }

    let header: BareHeader =
        parser::parse_bare_header(&response_buffer).expect("Parsing offsets and header failed");

    let advert = server
        .advertisements
        .choose(&mut rand::thread_rng())
        .unwrap();
    let added_size = response_writer::insert_txt_record_to_additional(
        &mut response_buffer,
        header.arcount,
        advert,
        header.additional_offset,
    )
    .expect("Inserting TXT record failed");

    Ok(added_size)
}

fn zero_out_vector(buffer: &mut [u8]) {
    for i in 0..buffer.len() {
        buffer[i] = 0;
    }
}
