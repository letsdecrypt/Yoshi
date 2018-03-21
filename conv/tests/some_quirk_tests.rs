#[cfg(test)]
mod tests {
    #[test]
    fn can_vec_equals_binary_string() {
        let v = [0x31u8, 0x32, 0x33, 0x34];
        assert_eq!(&v, b"1234");
    }
}
