// Functions relating to serializing into wire-encoded DNS message formats

/// Returns whether a string fits the criteria for a <character-string> defined in rfc1035#section-3.3
pub fn is_valid_character_string(message: &str) -> Result<(), &'static str> {
    if !message.is_ascii() {
        return Err("message is not pure ascii");
    }
    if message.len() > 256 {
        return Err("message is too long to fit in a character string");
    }
    return Ok(());
}

/// Convert a string to a <character-string> defined in rfc1035#section-3.3 and appends it to a vector
pub fn push_character_string(message: &str, bytes: &mut Vec<u8>) -> Result<(), &'static str> {
    let _validity = match is_valid_character_string(message) {
        Ok(_) => (),
        Err(e) => return Err(e),
    };

    bytes.push(message.len() as u8);
    for val in message.as_bytes() {
        bytes.push(*val);
    }

    return Ok(());
}

/// Pushes an array in format "3abc3com0" to a <domain-name> defined in rfc1035#section-4.1.2
/// it has this awkward interface because I can sidestep a
//  annoying performance details by enforcing an awkward format on the callers.
pub fn push_domain_name(message: &[u8], bytes: &mut Vec<u8>) -> Result<(), &'static str> {
    if message.len() > 253 {
        return Err("message is too long to fit in a domain name");
    }
    for val in message {
        bytes.push(*val);
    }
    return Ok(());
}

// TODO: move tests into seperate module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_string_to_dns_character_string() {
        let mut bytes: Vec<u8> = Vec::with_capacity(11);
        let res = push_character_string("aabcde  a!", &mut bytes);
        assert_eq!(res, Ok(()));
        assert_eq!(bytes, [10, 97, 97, 98, 99, 100, 101, 32, 32, 97, 33]);
    }

    #[test]
    fn convert_to_character_string_fails_on_non_ascii() {
        let mut bytes: Vec<u8> = Vec::with_capacity(1);
        let res = push_character_string("ü", &mut bytes);
        assert_eq!(res, Err("message is not pure ascii"));
    }

    #[test]
    fn convert_to_character_string_fails_with_long_string() {
        let mut bytes: Vec<u8> = Vec::with_capacity(1);
        let long_string = "a".repeat(257);
        let res = push_character_string(long_string.as_str(), &mut bytes);
        assert_eq!(res, Err("message is too long to fit in a character string"));
    }

    #[test]
    fn convert_string_to_domain_name() {
        let mut bytes: Vec<u8> = Vec::with_capacity(9);
        push_domain_name(b"\x03aaa\x03com\x00", &mut bytes).expect("Failed to push bytes");
        assert_eq!(bytes, [3, 97, 97, 97, 3, 99, 111, 109, 0]);
    }

    #[test]
    fn convert_string_to_domain_name_fails_with_long_string() {
        let mut bytes: Vec<u8> = Vec::with_capacity(9);
        let long_string = "a".repeat(254);
        let result = push_domain_name(long_string.as_str().as_bytes(), &mut bytes);
        assert_eq!(result, Err("message is too long to fit in a domain name"));
    }
}
