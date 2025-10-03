#![allow(unused)]
use obex_alpha_ii::deserialize_header;
use proptest::prelude::*;

proptest! {
    #[test]
    fn fuzz_header_decode_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..10_000)) {
        let _ = deserialize_header(&data);
    }
}
