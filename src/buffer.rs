#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutBuf<'a>(pub Option<&'a mut [u8]>, pub usize);
impl<'a> OutBuf<'a> {
    pub fn write_raw(&mut self, buf: &[u8]) {
        if let Some(buffer) = &mut self.0 {
            assert!(buffer.len() >= buf.len())
        }
        // rest of function cannot panic
        self.1 += buf.len();
        if let Some(buffer) = self.0.take() {
            let len = buffer.len() - buf.len();
            let (start, end) = buffer.split_at_mut(len);
            end.copy_from_slice(buf);
            drop(end);
            self.0 = Some(start);
        }
    }

    pub fn write(&mut self, tag: u8, cb: &dyn Fn(&mut Self)) -> usize {
        use std::mem::size_of;
        let start = self.1;
        cb(self);
        let len = self.1 - start;
        if len < 0x80 {
            self.write_raw(&[tag, len as u8]);
        } else {
            let bytes = size_of::<usize>()
                - (len.leading_zeros() as usize + size_of::<usize>() - 1) / size_of::<usize>();
            self.write_raw(&len.to_be_bytes()[bytes..]);
            self.write_raw(&[tag, bytes as u8 | 0x80]);
        }
        self.1 - start
    }

    pub fn write_fixed(&mut self, size: usize, cb: &dyn Fn(&mut [u8])) {
        self.1 += size;
        if let Some(buffer) = self.0.take() {
            let len = buffer.len() - size;
            let (start, end) = buffer.split_at_mut(len);
            cb(end);
            drop(end);
            self.0 = Some(start);
        }
    }

    pub fn bit_string(&mut self, buf: &[u8]) -> usize {
        self.write(super::BIT_STRING, &|writer| {
            writer.write_raw(buf);
            writer.write_raw(&[0]);
        })
    }

    pub fn nonnegative_integer(&mut self, buf: &[u8]) -> usize {
        self.write(super::INTEGER, &|writer| match buf.iter().position(|&e| e != 0) {
            None => writer.write_raw(&[0]),
            Some(e) => {
                writer.write_raw(&buf[e..]);
                assert_eq!(buf[e], 0x1);
                if (buf[e] & 128) != 0 {
                    writer.write_raw(&[0])
                }
            },
        })
    }

    pub fn x509_time(&mut self, time: &super::time::X509Time) {
        self.write_fixed(time.asn1_length() as usize, &|s| time.write_time_choice(s))
    }

    pub fn optional_boolean(&mut self, val: bool) {
        if val {
            self.write_raw(&[1, 1, 255])
        }
    }
}
pub struct FmtBuf<'a>(Option<&'a mut [u8]>);
impl<'a> FmtBuf<'a> {
    pub fn new(slice: &'a mut [u8]) -> Self { Self(Some(slice)) }
}
impl<'a> core::fmt::Write for FmtBuf<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let slice = self.0.take().unwrap();
        let bytes: &[u8] = s.as_ref();
        let (a, b): (&'a mut [u8], &'a mut [u8]) = slice.split_at_mut(bytes.len());
        a.copy_from_slice(bytes);
        self.0 = Some(b);
        Ok(())
    }
}
pub fn encode(data: &dyn Fn(&mut OutBuf)) -> Vec<u8> {
    let mut buf = OutBuf(None, 0);
    data(&mut buf);
    let len = buf.1;
    let mut vec = vec![0; len];
    buf = OutBuf(Some(&mut *vec), 0);
    data(&mut buf);
    assert_eq!(buf, OutBuf(Some(&mut [][..]), len));
    vec
}
