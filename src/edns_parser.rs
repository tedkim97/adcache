// https://datatracker.ietf.org/doc/html/rfc6891#section-1


mod EDNS_TTL {
    pub const EXTENDED_RCODE: u32 = 0b1111_1111_0000_0000_0000_0000_0000_0000
    pub const VERSION: u32 = 0b0000_0000_1111_1111_0000_0000_0000_0000;
    pub const DO: u32 = 0b0000_0000_0000_0000_1000_0000_0000_0000;
    pub const Z: u32 = 0b0000_0000_0000_0000_0111_1111_1111_1111;
}

// let time_to_live = i32::from_be_bytes(bytes[8..12].try_into().unwrap());
