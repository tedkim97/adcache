use crate::constants;

#[derive(Debug)]
/// Not a pure representation of a DNS message header.
/// Only includes fields needed for advertising
pub struct BareHeader {
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub question_offset: usize,
    pub answer_offset: usize,
    pub nameserver_offset: usize,
    pub additional_offset: usize,
}

pub fn parse_bare_header(bytes: &[u8]) -> Result<BareHeader, &'static str> {
    let mut bh = BareHeader {
        qdcount: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
        ancount: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
        nscount: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        arcount: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
        question_offset: 0,
        answer_offset: 0,
        nameserver_offset: 0,
        additional_offset: 0,
    };

    let mut pointer: usize = 0;
    pointer += 12; // skip the header offset
    for _i in 0..bh.qdcount {
        skip_over_question(bytes, &mut pointer);
    }
    bh.question_offset = pointer;
    for _i in 0..bh.ancount {
        skip_over_rr(bytes, &mut pointer);
    }
    bh.answer_offset = pointer;
    for _i in 0..bh.nscount {
        skip_over_rr(bytes, &mut pointer);
    }
    bh.nameserver_offset = pointer;
    for _i in 0..bh.arcount {
        skip_over_rr(bytes, &mut pointer);
    }
    bh.additional_offset = pointer;

    Ok(bh)
}

pub fn parse_dnssec_bit(bytes: &[u8]) -> bool {
    let mut pointer: usize = 0;
    while bytes[pointer] != 0 {
        pointer += 1;
    }
    pointer += 1; // factor in the extra 0 "domain name 0, needs to be marked with a 0"
    let _ = u16::from_be_bytes(bytes[pointer..(pointer + 2)].try_into().unwrap());
    let _ = u16::from_be_bytes(bytes[(pointer + 2)..(pointer + 4)].try_into().unwrap());
    // TYPE (uint16) + CLASS (uint16)
    pointer += 4;
    let ttl = u32::from_be_bytes(bytes[pointer..(pointer + 4)].try_into().unwrap());
    let do_bit: bool = (ttl & constants::edns_masks::DO) > 0;
    return do_bit;
}

/// Jumps the pointer over the question section in a raw DNS packet
pub fn skip_over_question(buf: &[u8], pointer_offset: &mut usize) {
    skip_domain_name(buf, pointer_offset);
    *pointer_offset += 4;
}

/// Jumps the pointer over a raw-wire encoded RR in a DNS packet
pub fn skip_over_rr(buf: &[u8], pointer_offset: &mut usize) {
    skip_domain_name(buf, pointer_offset);
    // Skip the TYPE (u16), CLASS (u16), TTL (u32) values within RFC 1035
    *pointer_offset += 2 + 2 + 4;
    let rdlength: usize = parse_u16(buf, pointer_offset).try_into().unwrap();
    *pointer_offset += rdlength;
    return;
}

/// Jumps the pointer over a domain name, defined as the sequence of labels
/// in RFC 1035. This should sufficiently ignore DNS compression complications.
pub fn skip_domain_name(buf: &[u8], pointer_offset: &mut usize) {
    // TODO - potentially think of branchless way of performing this op
    if buf[*pointer_offset] & 0b1100_0000 > 0 {
        *pointer_offset += 2;
        return;
    }
    while buf[*pointer_offset] != 0 {
        *pointer_offset += 1;
    }
    // This offset is necessary
    *pointer_offset += 1;
}

/// Parses a u16 from a network byte order (big endian) given a buffer and
/// pointer offset. This updates the pointer offset after the u16
pub fn parse_u16(buf: &[u8], pointer_offset: &mut usize) -> u16 {
    let val: [u8; 2] = buf[*pointer_offset..(*pointer_offset + 2)]
        .try_into()
        .unwrap();
    *pointer_offset += 2;
    return u16::from_be_bytes(val);
}

// TODO: move tests into seperate module
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_u16_test() {
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 2] = [2, 1];
        assert_eq!(parse_u16(&reference_buffer, &mut pointer), 513);
        assert_eq!(pointer, 2);
    }
    #[test]
    fn parse_u16_symmetrical() {
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 2] = [1, 1];
        assert_eq!(parse_u16(&reference_buffer, &mut pointer), 257);
        assert_eq!(pointer, 2);
    }
    #[test]
    fn parse_u16_longer_buffer() {
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 3] = [1, 1, 1];
        assert_eq!(parse_u16(&reference_buffer, &mut pointer), 257);
        assert_eq!(pointer, 2);
    }
    #[test]
    #[should_panic()]
    fn parse_u16_short_buffer_causes_panic() {
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 1] = [1];
        assert_eq!(parse_u16(&reference_buffer, &mut pointer), 257);
    }
    #[test]
    fn skip_domain_name_test() {
        // www.whitehouse.gov. to domain name encoding
        // 3 (length octet), 119 (w), 119 (w), 119 (w), 10 (length octet), 119 (w), 104 (h), 105 (i), 116 (t), 101 (e), 104 (h), 111 (o), 117 (u), 115 (s), 101 (e), 3 (length octet), 103 (g), 111 (o), 118 (v), 0 (terminanting character)
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 20] = [
            3, 119, 119, 119, 10, 119, 104, 105, 116, 101, 104, 111, 117, 115, 101, 3, 103, 111,
            118, 0,
        ];
        skip_domain_name(&reference_buffer, &mut pointer);
        assert_eq!(pointer, 20);
    }
    #[test]
    #[should_panic()]
    fn skip_domain_name_no_0_causes_panic() {
        let mut pointer: usize = 0;
        let reference_buffer: [u8; 4] = [1, 1, 1, 1];
        skip_domain_name(&reference_buffer, &mut pointer);
        assert_eq!(pointer, 5);
    }

    #[test]
    fn skip_question_test() {
        // www.whitehouse.gov. to domain name encoding
        // 3 (length octet), 119 (w), 119 (w), 119 (w), 10 (length octet), 119 (w), 104 (h), 105 (i), 116 (t), 101 (e), 104 (h), 111 (o), 117 (u), 115 (s), 101 (e), 3 (length octet), 103 (g), 111 (o), 118 (v), 0 (terminanting character)
        let mut pointer: usize = 0;
        let question_for_a_record: [u8; 24] = [
            3, 119, 119, 119, 10, 119, 104, 105, 116, 101, 104, 111, 117, 115, 101, 3, 103, 111,
            118, 0, 0, 1, 0, 1,
        ];
        skip_over_question(&question_for_a_record, &mut pointer);
        assert_eq!(pointer, 24);
    }

    #[test]
    fn skip_question_test_complete_buffer() {
        // www.whitehouse.gov. to domain name encoding
        // 3 (length octet), 119 (w), 119 (w), 119 (w), 10 (length octet), 119 (w), 104 (h), 105 (i), 116 (t), 101 (e), 104 (h), 111 (o), 117 (u), 115 (s), 101 (e), 3 (length octet), 103 (g), 111 (o), 118 (v), 0 (terminanting character)
        let mut pointer: usize = 0;
        let question_for_a_record: [u8; 25] = [
            10, 119, 104, 105, 116, 101, 104, 111, 117, 115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1,
            255, 255, 255, 255, 255,
        ];
        skip_over_question(&question_for_a_record, &mut pointer);
        assert_eq!(pointer, 20);
    }

    #[test]
    fn skips_dns_compressed_label_correctly() {
        let mut pointer: usize = 0;
        let dns_compressed_label: [u8; 6] = [192, 12, 5, 5, 5, 5]; // The 5 bytes are picked randomly
        skip_domain_name(&dns_compressed_label, &mut pointer);
        assert_eq!(pointer, 2);
    }

    #[test]
    fn parse_offsets_of_dnscompressed_response() {
        // made up response for whitehouse.gov
        let dns_response = [
            0, 1, 129, 128, 0, 1, 0, 1, 0, 0, 0, 0, 10, 119, 104, 105, 116, 101, 104, 111, 117,
            115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 1, 39, 0, 4, 2,
            2, 2, 2,
        ];
        let header =
            parse_bare_header(&dns_response).expect("failed to parse header from response");
        assert_eq!(header.question_offset, 32);
        assert_eq!(header.answer_offset, 48);
    }
}
