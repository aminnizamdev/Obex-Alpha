#![allow(unused)]
use obex_alpha_i::decode_partrec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn fuzz_partrec_decode_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..700_000)) {
        let _ = decode_partrec(&data);
    }
}
