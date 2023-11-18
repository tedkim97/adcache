use crate::constants;
use crate::parser::BareHeader;
use crate::serializer;

const TCP_OFFSET: usize = 2;

/// Includes a lot of TCP hacks
pub fn make_refused_response_tcp(
    dnspacket: &mut Vec<u8>,
    header: &BareHeader,
    err_msg: &str,
) -> Result<usize, &'static str> {
    convert_header_to_response(&mut dnspacket[TCP_OFFSET..], constants::rcodes::REFUSED);

    let added_size =
        insert_txt_record_by_offset(dnspacket, header.question_offset + TCP_OFFSET, 100, err_msg)
            .unwrap();
    let [new_an1, new_an2] = (header.ancount + 1).to_be_bytes();
    dnspacket[6 + TCP_OFFSET] = new_an1;
    dnspacket[7 + TCP_OFFSET] = new_an2;
    return Ok(added_size);
}

pub fn make_error_response(
    dnspacket: &mut Vec<u8>,
    header: &BareHeader,
    err_msg: &str,
) -> Result<usize, &'static str> {
    convert_header_to_response(dnspacket, constants::rcodes::REFUSED);
    let added_size: usize =
        insert_txt_record_to_answer(dnspacket, header.ancount, err_msg, header.answer_offset)
            .unwrap();
    let added_size2: usize = insert_txt_record_to_additional(
        dnspacket,
        header.arcount,
        err_msg,
        header.nameserver_offset + added_size,
    )
    .unwrap();
    let mut edns_added_size: usize = 0;
    if header.arcount > 0 {
        edns_added_size = overwrite_new_edns(
            dnspacket,
            header.nameserver_offset + added_size + added_size2,
        )
        .unwrap();
    }
    return Ok(added_size + added_size2 + edns_added_size);
}

// TODO: Consider enum for response_code for type safety
fn convert_header_to_response(dnspacket: &mut [u8], response_code: u8) {
    let mut flags: u16 = u16::from_be_bytes(dnspacket[2..4].try_into().unwrap());
    // Override the QR value to indicate that the packet is a DNS response
    flags |= constants::dns_header_masks::QR * constants::qr::RESPONSE;
    // Overwrite RCODE
    flags &= !constants::dns_header_masks::RCODE_MASK;
    flags |= u16::from(response_code);
    let [flag1, flag2] = flags.to_be_bytes();
    dnspacket[2] = flag1;
    dnspacket[3] = flag2;
}

fn overwrite_new_edns(
    dnspacket: &mut [u8],
    insertion_offset: usize,
) -> Result<usize, &'static str> {
    // Name of an OPT RR MUST BE 0
    dnspacket[insertion_offset] = 0;
    [
        dnspacket[insertion_offset + 1],
        dnspacket[insertion_offset + 2],
    ] = constants::rr_type::OPT.to_be_bytes();
    [
        dnspacket[insertion_offset + 3],
        dnspacket[insertion_offset + 4],
    ] = (512_u16).to_be_bytes();
    [
        dnspacket[insertion_offset + 5],
        dnspacket[insertion_offset + 6],
        dnspacket[insertion_offset + 7],
        dnspacket[insertion_offset + 8],
    ] = (0_u32).to_be_bytes();
    [
        dnspacket[insertion_offset + 9],
        dnspacket[insertion_offset + 10],
    ] = (0_u16).to_be_bytes();
    Ok(11)
}

pub fn insert_txt_record_to_answer(
    dnspacket: &mut Vec<u8>,
    ancount: u16,
    txt_msg: &str,
    insertion_offset: usize,
) -> Result<usize, &'static str> {
    let insertion_size: usize =
        insert_txt_record_by_offset(dnspacket, insertion_offset, 3600, txt_msg).unwrap();
    let [new_an1, new_an2] = (ancount + 1).to_be_bytes();
    dnspacket[6] = new_an1;
    dnspacket[7] = new_an2;
    Ok(insertion_size)
}

pub fn insert_txt_record_to_additional(
    dnspacket: &mut Vec<u8>,
    arcount: u16,
    txt_msg: &str,
    insertion_offset: usize,
) -> Result<usize, &'static str> {
    let insertion_size: usize =
        insert_txt_record_by_offset(dnspacket, insertion_offset, 7200, txt_msg).unwrap();
    let [new_ar1, new_ar2] = (arcount + 1).to_be_bytes();
    dnspacket[10] = new_ar1;
    dnspacket[11] = new_ar2;
    Ok(insertion_size)
}

// Note: since we're mutating the underlying vector with Vec::splice, we need to pass a mutable vector rather than a slice
/// record_name format should be like this: "3abc3com0"
fn insert_txt_record_by_offset(
    dnspacket: &mut Vec<u8>,
    insertion_offset: usize,
    ttl: u32,
    message: &str,
) -> Result<usize, &'static str> {
    match serializer::is_valid_character_string(message) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    let mut txt_record: Vec<u8> = Vec::with_capacity(255);
    // TODO replace DNS compression name for record_name (dig complains for some reason)
    // Use DNS Compression for the name (c00c)
    match serializer::push_domain_name(b"\xC0\x0C", &mut txt_record) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    for val in constants::rr_type::TXT.to_be_bytes() {
        txt_record.push(val);
    }
    for val in constants::rr_class::INTERNET.to_be_bytes() {
        txt_record.push(val);
    }
    for val in ttl.to_be_bytes() {
        txt_record.push(val);
    }
    let rd_len: u16 = (message.len() + 1).try_into().unwrap();
    for val in rd_len.to_be_bytes() {
        txt_record.push(val);
    }
    match serializer::push_character_string(message, &mut txt_record) {
        Ok(_) => (),
        Err(e) => return Err(e),
    }

    dnspacket.splice(insertion_offset..insertion_offset, txt_record);
    Ok(12 + message.as_bytes().len() + 1)
}

// TODO: move tests into seperate module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_query_to_response_noerror() {
        // ID{65535} => [255, 255]
        // HEADER{QR = 0, OPCODE = 0. AA = 0, TC = 0, RD = 1, RA = 0, Z = 0, AD = 1, CD = 1, RCODE = 0} =>
        // 0000010100110000 => [1, 48]
        // QDCOUNT{1} = [0, 1]
        // ANCOUNT{0} = [0, 0]
        // NSCOUNT{0} = [0, 0]
        // ARCOUNT{0} = [0, 0]
        // whitehouse.gov => [10 119 104 105 116 101 104 111 117 115 101 3 103 111 118 0]
        // QTYPE{1} = [0, 1]
        // QCLASS{1} = [0, 1]
        let mut dns_query = [
            255, 255, 1, 48, 0, 1, 0, 0, 0, 0, 0, 0, 10, 119, 104, 105, 116, 101, 104, 111, 117,
            115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1,
        ]
        .to_vec();
        let noerror_code: u8 = 0;
        convert_header_to_response(&mut dns_query, /*response_code=*/ noerror_code);

        let flags: u16 = u16::from_be_bytes(dns_query[2..4].try_into().unwrap());
        assert_eq!(
            flags & constants::dns_header_masks::QR,
            0b1000_0000_0000_0000
        );
        assert_eq!(
            flags & constants::dns_header_masks::RCODE_MASK,
            0b0000_0000_0000_0000
        );
    }

    #[test]
    fn convert_query_to_response_refused() {
        let mut dns_query = [
            255, 255, 1, 48, 0, 1, 0, 0, 0, 0, 0, 0, 10, 119, 104, 105, 116, 101, 104, 111, 117,
            115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1,
        ]
        .to_vec();
        let refused_code: u8 = 5;
        convert_header_to_response(&mut dns_query, /*response_code=*/ refused_code);

        let flags: u16 = u16::from_be_bytes(dns_query[2..4].try_into().unwrap());
        assert_eq!(
            flags & constants::dns_header_masks::QR,
            0b1000_0000_0000_0000
        );
        assert_eq!(
            flags & constants::dns_header_masks::RCODE_MASK,
            0b0000_0000_0000_0101
        );
    }

    #[test]
    fn insert_txt_record_by_offset_test() {
        let message = "this is a test.";
        // ID{65535} => [255, 255]
        // HEADER{QR = 0, OPCODE = 0. AA = 0, TC = 0, RD = 1, RA = 0, Z = 0, AD = 1, CD = 1, RCODE = 0} =>
        // 0000010100110000 => [1, 48]
        // QDCOUNT{1} = [0, 1]
        // ANCOUNT{0} = [0, 0]
        // NSCOUNT{0} = [0, 0]
        // ARCOUNT{0} = [0, 1]
        // whitehouse.gov => [10 119 104 105 116 101 104 111 117 115 101 3 103 111 118 0]
        // QTYPE{1} = [0, 1]
        // QCLASS{1} = [0, 1]
        // Noisy Bytes appended [111, 111, 111]
        let mut dns_query = [
            255, 255, 1, 48, 0, 1, 0, 0, 0, 0, 0, 1, 10, 119, 104, 105, 116, 101, 104, 111, 117,
            115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1, 111, 111, 111,
        ]
        .to_vec();

        let expected_packet = [
            255, 255, 1, 48, 0, 1, 0, 0, 0, 0, 0, 1, 10, 119, 104, 105, 116, 101, 104, 111, 117,
            115, 101, 3, 103, 111, 118, 0, 0, 1, 0, 1, 192, 12, 0, 16, 0, 1, 0, 0, 0, 10, 0, 16,
            15, 116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 116, 101, 115, 116, 46, 111, 111,
            111,
        ]
        .to_vec();
        let result = insert_txt_record_by_offset(&mut dns_query, 32, 10, message);
        // 12 = bytes added from Record info (Class, RDLen, etc)
        // 16 = bytes added from TXT record (u8_indicating_length + "this is a test.")
        assert_eq!(result, Ok(12 + 16));
        assert_eq!(dns_query, expected_packet);
    }
}
