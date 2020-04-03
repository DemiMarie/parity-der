use super::DerEncodable;

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
    pub fn write(&mut self, buf: &[u8], tag: u8) {
        use std::mem::size_of;
        let start = self.1;
        self.write_raw(buf);
        let len = self.1 - start;
        if len < 0x80 {
            self.write_raw(&[tag, len as u8]);
        } else {
            let bytes = size_of::<usize>()
                - (len.leading_zeros() as usize + size_of::<usize>() - 1) / size_of::<usize>();
            self.write_raw(&len.to_be_bytes()[bytes..]);
            self.write_raw(&[tag, bytes as u8 | 0x80]);
        }
    }
}

pub fn encode(data: &dyn DerEncodable) -> Vec<u8> {
    encode_cb(&|e| drop(data.encode(e)))
}

pub fn encode_cb(data: &dyn Fn(&mut OutBuf)) -> Vec<u8> {
    let mut buf = OutBuf(None, 0);
    data(&mut buf);
    let len = buf.1;
    let mut vec = vec![0; len];
    buf = OutBuf(Some(&mut *vec), 0);
    data(&mut buf);
    assert_eq!(buf, OutBuf(Some(&mut [][..]), len));
    vec
}
