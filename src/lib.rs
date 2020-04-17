mod buffer;
pub use buffer::{encode, OutBuf};

#[cfg(windows)]
use libc::gmtime;
#[cfg(not(windows))]
use libc::gmtime_r;

extern "C" {
    fn strftime(
        buf: *mut libc::c_char,
        len: libc::size_t,
        fmt: *const libc::c_char,
        time: *const libc::tm,
    ) -> libc::size_t;
}

fn check_time_range(time: u64) {
    if std::mem::size_of::<libc::time_t>() < 8 {
        assert!(time < u32::max_value() as _, "time overflowed 2038");
    }
}

fn encode_times_raw(buf: &mut [u8], time: u64) -> usize {
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
        let fmt = if t1.tm_year > 149 {
            b"\x18\x0f%Y%m%d%H%M%SZ\0"
        } else {
            b"\x17\x0d%y%m%d%H%M%SZ\0"
        };
        assert_eq!(
            strftime(
                buf.as_mut_ptr() as _,
                buf.len(),
                fmt.as_ptr() as *const _,
                t1
            ),
            (fmt[1] + 2) as usize
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

pub trait DerEncodable {
    fn encode_raw(&self, buffer: &mut OutBuf<'_>, token: Token) -> Priv;
    fn encode(&self, buffer: &mut OutBuf<'_>) -> Priv2 {
        use std::mem::size_of;
        let start = buffer.1;
        let Priv(tag) = self.encode_raw(buffer, Token {});
        let len = buffer.1 - start;
        if len < 0x80 {
            buffer.write_raw(&[tag, len as u8]);
        } else {
            let bytes = size_of::<usize>()
                - (len.leading_zeros() as usize + size_of::<usize>() - 1) / size_of::<usize>();
            buffer.write_raw(&len.to_be_bytes()[bytes..]);
            buffer.write_raw(&[tag, bytes as u8 | 0x80]);
        }
        Priv2
    }
}

mod r#priv {
    #[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
    pub struct Priv(pub u8);
    #[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
    pub struct Priv2;
    #[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
    pub struct Token {}
}

struct Sequence<'a, 'b: 'a>(&'a [&'b dyn DerEncodable]);

const CONTEXT_SPECIFIC: u8 = 1u8 << 7;
const CONSTRUCTED: u8 = 1u8 << 5;
const SEQUENCE: u8 = 0x10 | CONSTRUCTED;
const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const NULL: u8 = 0x05;
const OID: u8 = 0x06;
const UTCTIME: u8 = 0x17;
const GENERALIZEDTIME: u8 = 0x18;
impl DerEncodable for Sequence<'_, '_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        for i in self.0.iter().rev() {
            i.encode(buffer);
        }
        Priv(SEQUENCE)
    }
}
use r#priv::{Priv, Priv2, Token};

#[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
struct BitString<'a>(&'a [u8]);
struct OctetString<'a>(&'a dyn DerEncodable);

#[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
pub struct X509V3 {}

impl DerEncodable for X509V3 {
    fn encode_raw(&self, buf: &mut OutBuf, Token {}: Token) -> Priv {
        buf.write_raw(&[INTEGER, 1, 2]);
        Priv(CONSTRUCTED | CONTEXT_SPECIFIC)
    }
    fn encode(&self, buf: &mut OutBuf) -> Priv2 {
        buf.write_raw(&[
            CONSTRUCTED | CONTEXT_SPECIFIC,
            3,
            INTEGER,
            1,
            2,
            INTEGER,
            1,
            1,
        ]);
        Priv2
    }
}

#[derive(Debug, Clone, Copy, Ord, PartialEq, Eq, PartialOrd, Hash)]
pub struct PositiveInteger {
    inner: u64,
}

impl PositiveInteger {
    pub fn new(inner: u64) -> Self {
        Self { inner }
    }
}

impl DerEncodable for PositiveInteger {
    fn encode_raw(&self, buf: &mut OutBuf, Token {}: Token) -> Priv {
        let inner = self.inner;
        if inner == 0 {
            buf.write_raw(&[0]);
            return Priv(INTEGER);
        }
        let zeros = (inner.leading_zeros() as usize) / 8;
        let bytes = inner.to_be_bytes();
        buf.write_raw(&bytes[zeros..]);
        if bytes[zeros] > 127 {
            buf.write_raw(&[0]);
        }
        Priv(INTEGER)
    }
}

pub struct Raw<'a> {
    pub raw: &'a [u8],
    pub tag: u8,
}

impl DerEncodable for Raw<'_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        buffer.write_raw(self.raw);
        Priv(self.tag)
    }
}

pub struct TimeChoice {
    time: u64,
}

pub struct Extension<'a, 'b> {
    oid: &'a [u8],
    critical: bool,
    value: &'b dyn DerEncodable,
}

impl<'a, 'b> Extension<'a, 'b> {
    pub fn new(oid: &'a [u8], critical: bool, value: &'b dyn DerEncodable) -> Self {
        Self {
            oid,
            critical,
            value,
        }
    }
}

pub struct Validity {
    not_before: u64,
    not_after: u64,
}

impl DerEncodable for Validity {
    fn encode_raw(&self, _buffer: &mut OutBuf<'_>, Token {}: Token) -> Priv {
        unimplemented!()
    }
    fn encode(&self, buffer: &mut OutBuf) -> Priv2 {
        let buf = &mut [0; 38];
        let len = encode_times(buf, self.not_before, self.not_after);
        buffer.write_raw(&buf[..len]);
        Priv2
    }
}

fn encode_certificate(
    not_before: u64,
    not_after: u64,
    algorithm: &[u8],
    key: &[u8],
    sigalg: &[u8],
) -> Vec<u8> {
    encode(&Sequence(&[
        &Sequence(&[
            (&X509V3 {}) as &dyn DerEncodable,
            &Raw {
                tag: SEQUENCE,
                raw: sigalg,
            },
            &Sequence(&[]),
            &Validity {
                not_before,
                not_after,
            },
            &Sequence(&[
                &Raw {
                    tag: SEQUENCE,
                    raw: algorithm,
                },
                &BitString(key),
            ]),
            &WrappedExtensions {
                data: &[&Extension {
                    oid: &[6, 3, 85, 29, 19],
                    critical: true,
                    value: &Sequence(&[]),
                }],
            },
        ]) as &dyn DerEncodable,
        &Raw {
            tag: SEQUENCE,
            raw: sigalg,
        },
        &BitString(&[]),
    ]))
}

struct WrappedExtensions<'c, 'd> {
    data: &'c [&'d dyn DerEncodable],
}

impl DerEncodable for WrappedExtensions<'_, '_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        Sequence(self.data).encode(buffer);
        Priv(CONSTRUCTED | CONTEXT_SPECIFIC | 3)
    }
}

impl DerEncodable for Extension<'_, '_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        OctetString(self.value).encode(buffer);
        if self.critical {
            buffer.write_raw(&[BOOLEAN, 1, 255]);
        }
        buffer.write_raw(self.oid);
        Priv(SEQUENCE)
    }
}

impl DerEncodable for BitString<'_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        buffer.write_raw(self.0);
        buffer.write_raw(&[0u8]);
        Priv(BIT_STRING)
    }
}

impl DerEncodable for OctetString<'_> {
    fn encode_raw(&self, buffer: &mut OutBuf, Token {}: Token) -> Priv {
        self.0.encode(buffer);
        Priv(OCTET_STRING)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn get_or_works() {
        let mut b = OutBuf(None, 0);
        b.write_raw(b"a");
        assert_eq!(b, OutBuf(None, 1));
        Sequence(&[]).encode(&mut b);
        assert_eq!(b, OutBuf(None, 3));
        let mut v = vec![0u8; 2];
        let mut b = OutBuf(Some(&mut *v), 0);
        Sequence(&[]).encode(&mut b);
        assert_eq!(b, OutBuf(Some(&mut [][..]), 2));
        assert_eq!(v, vec![SEQUENCE, 0]);
    }
    #[test]
    fn encode_works() {
        use ring::{error::Unspecified, io::der};
        assert_eq!(der::Tag::Sequence as u8, SEQUENCE);
        assert_eq!(der::Tag::Boolean as u8, BOOLEAN);
        assert_eq!(encode(&Sequence(&[])), vec![SEQUENCE, 0]);
        assert_eq!(der::Tag::Integer as u8, INTEGER);
        assert_eq!(
            der::Tag::ContextSpecificConstructed0 as u8,
            CONTEXT_SPECIFIC | CONSTRUCTED
        );
        assert_eq!(
            encode(&Sequence(&[&Sequence(&[]), &Sequence(&[])])),
            vec![SEQUENCE, 4, SEQUENCE, 0, SEQUENCE, 0]
        );
        assert_eq!(encode(&PositiveInteger { inner: 0 }), vec![INTEGER, 1, 0]);
        assert_eq!(encode(&PositiveInteger { inner: 1 }), vec![INTEGER, 1, 1]);
        let buf = &mut [0u8; 38];
        let len = encode_times(buf, 1585162134, 1585162134 + 8640000000);
        println!("DER output is {:?}", &buf[..len]);
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cert = encode_certificate(now, now, b.as_ref(), &[], b.as_ref());
        untrusted::Input::from(&[INTEGER, 1, 1])
            .read_all(Unspecified, der::positive_integer)
            .unwrap();
        let input = untrusted::Input::from(&cert);
        input
            .read_all(0, |reader| {
                der::nested(reader, der::Tag::Sequence, 1, |reader| {
                    der::nested(reader, der::Tag::Sequence, 2, |reader| {
                        Ok(println!(
                            "{:?}",
                            reader.read_bytes_to_end().as_slice_less_safe()
                        ))
                    })?;
                    der::nested(reader, der::Tag::Sequence, 3, |reader| {
                        Ok(println!(
                            "{:?}",
                            reader.read_bytes_to_end().as_slice_less_safe()
                        ))
                    })?;
                    Ok(der::bit_string_with_no_unused_bits(reader).unwrap())
                })
            })
            .unwrap();
        std::fs::write("output.der", &cert).unwrap();
        webpki::EndEntityCert::from(&cert).unwrap();
    }
}
