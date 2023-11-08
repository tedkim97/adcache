// rfc1035
// RFC 2929 Section 2.0

mod header_bits {
    pub const QR: u16 = 0b1000_0000_0000_0000;
    pub const AA: u16 = 0b0000_0100_0000_0000;
    pub const TC: u16 = 0b0000_0010_0000_0000;
    pub const RD: u16 = 0b0000_0001_0000_0000;
    pub const RA: u16 = 0b0000_0000_1000_0000;
    pub const AD: u16 = 0b0000_0000_0010_0000;
    pub const CD: u16 = 0b0000_0000_0001_0000;
    pub const OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub const RCODE_MASK: u16 = 0b0000_0000_0000_1111;
    // Not a header bit - TODO delete this
    pub const DO: u32 = 0b0000_0000_0000_0000_1000_0000_0000_0000;
}

// TODO: bool in rust aren't 1 bit, we should reduce
// the memory footprint of Header by
// finding a packing lib
#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub adcount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn to_bytes(&self) -> Result<[u8; 12], &'static str> {
        let mut header: [u8; 12] = [0; 12];
        match self.serialize(&mut header) {
            Ok(_) => return Ok(header),
            Err(_) => return Err("failed to serialize bytes"),
        }
    }

    pub fn serialize(&self, header: &mut [u8; 12]) -> Result<(), &'static str> {
        // Serialize ID
        let [ip1, ip2] = self.id.to_be_bytes();
        header[0] = ip1;
        header[1] = ip2;
        // Deserialze QR
        let mut flags: u16 = header_bits::QR * (self.qr as u16);
        // Deserialze OPCODE
        flags |= u16::from(self.opcode) << 11;
        // Serialize AA
        flags |= header_bits::AA * (self.aa as u16);
        // Serialize TC
        flags |= header_bits::TC * (self.tc as u16);
        // Serialize RD
        flags |= header_bits::RD * (self.rd as u16);
        // Serialize RA
        flags |= header_bits::RA * (self.ra as u16);
        // Serialize AD
        flags |= header_bits::AD * (self.ad as u16);
        // Serialize CD
        flags |= header_bits::CD * (self.cd as u16);
        // Serialize RCODE
        flags |= u16::from(self.rcode);
        let [flag1, flag2] = flags.to_be_bytes();
        header[2] = flag1;
        header[3] = flag2;
        // Serialize QDCOUNT
        let [qd1, qd2] = self.qdcount.to_be_bytes();
        header[4] = qd1;
        header[5] = qd2;
        // Serialize ADCOUNT
        let [ad1, ad2] = self.adcount.to_be_bytes();
        header[6] = ad1;
        header[7] = ad2;
        // Serialize NSCOUNT
        let [ns1, ns2] = self.nscount.to_be_bytes();
        header[8] = ns1;
        header[9] = ns2;
        // Serialize ARCOUNT
        let [ar1, ar2] = self.arcount.to_be_bytes();
        header[10] = ar1;
        header[11] = ar2;
        return Ok(());
    }
}

// Convert bytes into header
pub fn deserialize(bytes: &[u8]) -> Result<Header, &'static str> {
    if bytes.len() < 12 {
        return Err("Message is too short to contain a header");
    }
    let id = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    let flags = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    let qr: bool = (flags & header_bits::QR) > 0;
    let opcode: u8 = ((flags & header_bits::OPCODE_MASK) >> 11 as u8)
        .try_into()
        .unwrap();
    let aa: bool = (flags & header_bits::AA) > 0;
    let tc: bool = (flags & header_bits::TC) > 0;
    let rd: bool = (flags & header_bits::RD) > 0;
    let ra: bool = (flags & header_bits::RA) > 0;
    let ad: bool = (flags & header_bits::AD) > 0;
    let cd: bool = (flags & header_bits::CD) > 0;
    let rcode: u8 = (flags & header_bits::RCODE_MASK) as u8;
    let qdcount = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
    let adcount = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
    let nscount = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
    let arcount = u16::from_be_bytes(bytes[10..12].try_into().unwrap());

    return Ok(Header {
        id: id,
        qr: qr,
        opcode: opcode,
        aa: aa,
        tc: tc,
        rd: rd,
        ra: ra,
        ad: ad,
        cd: cd,
        rcode: rcode,
        qdcount: qdcount,
        adcount: adcount,
        nscount: nscount,
        arcount: arcount,
    });
}

pub fn get_offset(bytes: &[u8], qdcount: u16, adcount: u16, nscount:u16, arcount: u16) -> u16 {
    return 0;
}

pub fn parse_over_question(bytes: &[u8]) -> usize {
    let mut pointer: usize = 0;
    while bytes[pointer] != 0 {
        pointer += 1;
    }
    println!("Domain length = {}", pointer);
    return pointer + 2 + 2;
}

pub fn parse_over_rr(bytes: &[u8]) -> u16 {
    return 0;
}

pub fn parse_dnssec_bit(bytes: &[u8]) -> bool {
    // perhaps refactor this out to just set the pointer to +2 because EDNS always set this value to [0, 0]
    let mut pointer: usize = 0;
    while bytes[pointer] != 0 {
        pointer += 1;
    }
    pointer += 1; // factor in the extra 0 "domain name 0, needs to be marked with a 0"
    let rr_type: u16 = u16::from_be_bytes(bytes[pointer..(pointer + 2)].try_into().unwrap());
    println!("Printing the TYPE (should be OPT = 41) = {}", rr_type);
    let rr_class: u16 = u16::from_be_bytes(bytes[(pointer + 2)..(pointer + 4)].try_into().unwrap());
    println!("Printing the requestor's UDP payload size = {}", rr_class);
    // TYPE (uint16) + CLASS (uint16)
    pointer = pointer + 2 + 2;
    let ttl = u32::from_be_bytes(bytes[pointer..(pointer+4)].try_into().unwrap());
    let do_bit: bool = (ttl & header_bits::DO) > 0;
    return do_bit;
}

pub fn skip_domain_name(buf: &[u8], pointer_offset: &mut usize) {
    while buf[*pointer_offset] != 0 {
        *pointer_offset += 1;
    }
    // This offset is necessary
    *pointer_offset += 1;
}

// Parses a u16 from network byte order (big endian) into host OS byte order
// also increments the pointer in the necessary way
pub fn parse_u16(buf: &[u8], pointer_offset: &mut usize) -> u16{
    let val: u16 = buf[pointer..(pointer + 2)].try_into().unwrap();
    pointer_offset += 2;
    return u16::from_be_bytes(val);
}