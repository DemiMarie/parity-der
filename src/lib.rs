mod buffer;
mod time;
pub use buffer::{encode, OutBuf};
use core::convert::TryFrom;
pub use time::{days_to_ymd, X509Time, MAX_ASN1_TIMESTAMP};
// 253402300799
const MAX: u64 = (146097 * 25 - 719468 - 60) * 86400 - 1;
pub const CONTEXT_SPECIFIC: u8 = 1u8 << 7;
pub const CONSTRUCTED: u8 = 1u8 << 5;
pub const SEQUENCE: u8 = 0x10 | CONSTRUCTED;
pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const UTCTIME: u8 = 0x17;
pub const GENERALIZEDTIME: u8 = 0x18;

pub fn encode_certificate(
    not_before: u64, not_after: u64, algorithm: &[u8], sig: &[u8], key: &[u8], sigalg: &[u8],
) -> Result<Vec<u8>, ()> {
    let not_before = X509Time::try_from(not_before)?;
    let not_after = X509Time::try_from(not_after)?;
    Ok(encode(&|writer: &mut OutBuf| {
        writer.write(SEQUENCE, &|writer| {
            writer.bit_string(sig);
            writer.write(SEQUENCE, &|writer| writer.write_raw(sigalg));
            writer.write(SEQUENCE, &|writer| {
                writer.write(CONSTRUCTED | CONTEXT_SPECIFIC | 3, &|writer| {
                    writer.write(SEQUENCE, &|writer| {
                        writer.write(SEQUENCE, &|writer| {
                            writer.write(OCTET_STRING, &|writer| {
                                writer.write(SEQUENCE, &|_| ());
                            });
                            writer.optional_boolean(true);
                            writer.write_raw(&[6, 3, 85, 29, 19]);
                        });
                    });
                });
                writer.write(SEQUENCE, &|writer| {
                    writer.bit_string(key);
                    writer.write(SEQUENCE, &|writer| writer.write_raw(algorithm));
                });
                writer.write(SEQUENCE, &|_| ());
                writer.write(SEQUENCE, &|writer| {
                    writer.x509_time(&not_after);
                    writer.x509_time(&not_before);
                });
                writer.write(SEQUENCE, &|_| ());
                writer.write(SEQUENCE, &|writer| writer.write_raw(sigalg));
                writer.nonnegative_integer(&[0x1]);
                writer.write_raw(&[CONSTRUCTED | CONTEXT_SPECIFIC, 3, INTEGER, 1, 2]);
            });
        });
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encode_works() {
        use ring::{error::Unspecified, io::der};
        use std::convert::TryInto;
        use time::DecomposedGmt;
        assert_eq!(der::Tag::Boolean as u8, BOOLEAN);
        assert_eq!(der::Tag::Integer as u8, INTEGER);
        assert_eq!(der::Tag::ContextSpecificConstructed0 as u8, CONTEXT_SPECIFIC | CONSTRUCTED);
        let not_before = 1585162134;
        let not_after = MAX;
        let not_before: time::X509Time = time::DecomposedGmt::parse(not_before).try_into().unwrap();
        let not_after: time::X509Time = time::DecomposedGmt::parse(not_after).try_into().unwrap();
        let b = include_bytes!("../alg-ed25519.der");
        let cert = encode_certificate(1585162134, MAX, b.as_ref(), &[], &[], b.as_ref()).unwrap();
        untrusted::Input::from(&[INTEGER, 1, 1])
            .read_all(Unspecified, der::positive_integer)
            .unwrap();
        let input = untrusted::Input::from(&cert);
        input
            .read_all(0, |reader| {
                der::nested(reader, der::Tag::Sequence, 1, |reader| {
                    der::nested(reader, der::Tag::Sequence, 2, |reader| {
                        Ok(println!("{:?}", reader.read_bytes_to_end().as_slice_less_safe()))
                    })?;
                    der::nested(reader, der::Tag::Sequence, 3, |reader| {
                        Ok(println!("{:?}", reader.read_bytes_to_end().as_slice_less_safe()))
                    })?;
                    Ok(der::bit_string_with_no_unused_bits(reader).unwrap())
                })
            })
            .unwrap();
        std::fs::write("output.der", &cert).unwrap();
        webpki::EndEntityCert::from(&cert).unwrap();
    }
}
