// RFC 2929 Section 2
pub mod dns_header_masks {
    pub const QR: u16 = 0b1000_0000_0000_0000;
    pub const _AA: u16 = 0b0000_0100_0000_0000;
    pub const _TC: u16 = 0b0000_0010_0000_0000;
    pub const _RD: u16 = 0b0000_0001_0000_0000;
    pub const _RA: u16 = 0b0000_0000_1000_0000;
    pub const _AD: u16 = 0b0000_0000_0010_0000;
    pub const _CD: u16 = 0b0000_0000_0001_0000;
    pub const _OPCODE_MASK: u16 = 0b0111_1000_0000_0000;
    pub const RCODE_MASK: u16 = 0b0000_0000_0000_1111;
}

// RFC 6891
pub mod edns_masks {
    pub const _EXTENDED_RCODE: u32 = 0b1111_1111_0000_0000_0000_0000_0000_0000;
    pub const _VERSION: u32 = 0b0000_0000_1111_1111_0000_0000_0000_0000;
    pub const DO: u32 = 0b0000_0000_0000_0000_1000_0000_0000_0000;
    pub const _Z: u32 = 0b0000_0000_0000_0000_0111_1111_1111_1111;
}

// www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
pub mod rcodes {
    pub const _NO_ERROR: u8 = 0;
    pub const _FORM_ERR: u8 = 1;
    pub const _SERV_FAIL: u8 = 2;
    pub const _NX_DOMAIN: u8 = 3;
    pub const _NOT_IMP: u8 = 4;
    pub const REFUSED: u8 = 5;
}

// Special values crammed in here:
pub mod qr {
    pub const RESPONSE: u16 = 1;
    pub const _QUERY: u16 = 0;
}

// www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
pub mod rr_type {
    pub const _A: u16 = 1;
    pub const TXT: u16 = 16;
    pub const _AAAA: u16 = 28;
    pub const OPT: u16 = 41;
}

// www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-3
pub mod rr_class {
    pub const INTERNET: u16 = 1;
}
