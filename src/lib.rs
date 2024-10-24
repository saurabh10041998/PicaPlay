use pcap::Error;
pub fn sample_test() -> String {
    String::from("This is test string")
}

pub fn get_packet_count(pcap_name: &'static str) -> Result<usize, Error> {
    let mut count = 0;
    let mut capture = pcap::Capture::from_file(pcap_name)?;
    while let Ok(_) = capture.next_packet() {
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_simple_string_return() {
        assert_eq!(sample_test(), String::from("This is test string"));
    }

    #[test]
    fn test_counting_pcaps() {
        let count_result = get_packet_count("pcaps/bgp.pcap");
        assert!(count_result.is_ok());
        assert_eq!(count_result.unwrap(), 157);
    }
}
