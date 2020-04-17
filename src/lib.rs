mod buffer;
mod time;
pub use buffer::{encode, OutBuf};
use core::convert::TryFrom;
pub use time::{days_to_ymd, DecomposedGmt, X509Time, MAX_ASN1_TIMESTAMP};
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
fn check_time_range(time: u64) {
    if std::mem::size_of::<libc::time_t>() < 8 {
        assert!(time < u32::max_value() as _, "time overflowed 2038");
    } else {
        assert!(time <= MAX, "time too large to represent in ASN.1");
    }
}
fn encode_times_raw(buf: &mut [u8], time: u64) -> usize {
    use core::convert::TryInto;
    check_time_range(time);
    unsafe {
        assert!(buf.len() >= 18);
        #[cfg(not(windows))]
        let mut t1: libc::tm = std::mem::zeroed();
        #[cfg(not(windows))]
        assert!(!gmtime_r(&(time as libc::time_t), &mut t1).is_null());
        #[cfg(not(windows))]
        let t1 = &t1;
        #[cfg(windows)]
        let t1 = gmtime(time as time_t);
        #[cfg(windows)]
        assert!(!t1.is_null());
        let t2 = time::DecomposedGmt::parse(time);
        assert_eq!(t1.tm_sec, t2.second() as _);
        assert_eq!(t1.tm_year as i64, t2.year() - 1900);
        assert_eq!(t1.tm_mon + 1, t2.month() as _);
        assert_eq!(t1.tm_mday, t2.day().try_into().unwrap());
        assert_eq!(t1.tm_hour, t2.hour().try_into().unwrap());
        assert_eq!(t1.tm_min, t2.minute().try_into().unwrap());
        let fmt =
            if t1.tm_year > 149 { b"\x18\x0f%Y%m%d%H%M%SZ\0" } else { b"\x17\x0d%y%m%d%H%M%SZ\0" };
        assert_eq!(
            strftime(buf.as_mut_ptr() as _, buf.len(), fmt.as_ptr() as *const _, t1,),
            (fmt[1] + 2) as usize,
            "libc bug at time {}",
            time
        );
        (fmt[1] + 2) as usize
    }
}
fn encode_times(buf: &mut [u8], time1: u64, time2: u64) -> usize {
    assert!(buf.len() >= 38);
    buf[0] = SEQUENCE;
    let mut len = 2;
    len += encode_times_raw(&mut buf[len..], time1);
    len += encode_times_raw(&mut buf[len..], time2);
    buf[1] = (len - 2) as _;
    buf[len] = SEQUENCE;
    buf[len + 1] = 0;
    len + 2
}
#[cfg(windows)]
use libc::gmtime;
#[cfg(not(windows))]
use libc::gmtime_r;
extern "C" {
    fn strftime(
        buf: *mut libc::c_char, len: libc::size_t, fmt: *const libc::c_char, time: *const libc::tm,
    ) -> libc::size_t;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_computations() {
        use time::DecomposedGmt;
        let gmt = DecomposedGmt::parse(1585162134);
        assert_eq!(gmt.year(), 2020);
        assert_eq!(gmt.month(), 3);
        assert_eq!(gmt.day(), 25);
        assert_eq!(gmt.hour(), 18);
        assert_eq!(gmt.minute(), 48);
        assert_eq!(gmt.second(), 54);
    }
    #[test]
    fn check_time_against_libc() {
        let mut i = 0;
        let mut buf = [0; 38];
        while i < MAX {
            encode_times_raw(&mut buf, i);
            i += 86400;
        }
    }
    #[test]
    fn encode_works() {
        use ring::{error::Unspecified, io::der};
        use std::convert::TryInto;
        use time::DecomposedGmt;
        assert_eq!(der::Tag::Boolean as u8, BOOLEAN);
        assert_eq!(der::Tag::Integer as u8, INTEGER);
        assert_eq!(der::Tag::ContextSpecificConstructed0 as u8, CONTEXT_SPECIFIC | CONSTRUCTED);
        let not_before = 1585162134;
        // let not_after = 1585162134 + 8640000000;
        let not_after = MAX;
        // let buf = &mut [0u8; 38];
        // let len = encode_times(buf, not_before, not_after);
        let not_before: time::X509Time = time::DecomposedGmt::parse(not_before).try_into().unwrap();
        let not_after: time::X509Time = time::DecomposedGmt::parse(not_after).try_into().unwrap();
        println!("made it here!");
        let bad: Vec<u8> = encode(&|writer| {
            writer.write(SEQUENCE, &|_| ());
            writer.write(SEQUENCE, &|writer| {
                writer.x509_time(&not_after);
                writer.x509_time(&not_before);
            });
        });
        println!("made it here!");
        #[cfg(any())]
        assert_eq!(
            core::str::from_utf8(&buf[..len]).unwrap(),
            core::str::from_utf8(&*bad).unwrap(),
        );
        #[cfg(any())]
        println!("DER output is {:?}", &buf[..len]);
        #[cfg(any())]
        untrusted::Input::from(&buf[..len])
            .read_all(Unspecified, |reader| {
                let seq1 = der::expect_tag_and_get_value(reader, der::Tag::Sequence).unwrap();
                seq1.read_all(Unspecified, |reader| {
                    for _ in 0..2 {
                        let (tag, str) = der::read_tag_and_get_value(reader).unwrap();
                        println!(
                            "Tag: {}, Output: {}",
                            tag,
                            std::str::from_utf8(str.as_slice_less_safe()).unwrap()
                        );
                    }
                    Ok(())
                })
                .expect("bug");
                assert!(der::expect_tag_and_get_value(reader, der::Tag::Sequence)
                    .unwrap()
                    .as_slice_less_safe()
                    .is_empty());
                Ok(())
            })
            .unwrap();
        let b = include_bytes!("../alg-ed25519.der");
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
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
