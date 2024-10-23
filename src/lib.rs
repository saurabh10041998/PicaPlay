pub fn sample_test() -> String { 
    String::from("This is test string")
}

#[cfg(test)]
pub mod tests {
    use super::*;
    #[test]
    fn test_simple_string_return() { 
        assert_eq!(sample_test(), String::from("This is test string"));
    }
}
