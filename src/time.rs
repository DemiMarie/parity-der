use core::convert::TryFrom;
fn seconds_to_dhms(seconds: u64) -> (u64, u8, u8, u8) {
    let days = seconds / 86400;
    let mut seconds = (seconds % 86400) as u32;
    let s = (seconds % 60) as u8;
    seconds /= 60;
    let m = (seconds % 60) as u8;
    (days, (seconds / 60) as u8, m, s)
}

// from Howard Hinnant. Public domain.
pub fn days_to_ymd(mut days: i64) -> (i64, u8, u8) {
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - (era * 146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp as i8 + if mp < 10 { 3 } else { -9i8 };
    (y + (m <= 2) as i64, m as _, d as _)
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct DecomposedGmt {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl DecomposedGmt {
    pub fn parse(seconds: u64) -> Self {
        let (days, hour, minute, second) = seconds_to_dhms(seconds);
        let (year, month, day) = days_to_ymd(days as _);
        Self { year, month, day, hour, minute, second }
    }

    pub fn year(&self) -> i64 { self.year }

    pub fn month(&self) -> u8 { self.month }

    pub fn day(&self) -> u8 { self.day }

    pub fn hour(&self) -> u8 { self.hour }

    pub fn minute(&self) -> u8 { self.minute }

    pub fn second(&self) -> u8 { self.second }
}

pub const MAX_ASN1_TIMESTAMP: u64 = 253402300799;
pub struct X509Time(DecomposedGmt);
impl TryFrom<u64> for X509Time {
    type Error = ();

    fn try_from(seconds: u64) -> Result<Self, ()> {
        if seconds > MAX_ASN1_TIMESTAMP {
            return Err(()) // cannot be represented in ASN.1
        }
        Ok(Self(DecomposedGmt::parse(seconds)))
    }
}

impl TryFrom<DecomposedGmt> for X509Time {
    type Error = ();

    fn try_from(t: DecomposedGmt) -> Result<Self, Self::Error> {
        if t.year > 9999 {
            Err(())
        } else {
            Ok(Self(t))
        }
    }
}

impl X509Time {
    pub fn asn1_length(&self) -> u8 {
        if self.0.year > 2049 {
            17
        } else {
            15
        }
    }

    pub fn year(&self) -> i64 { self.0.year }

    pub fn month(&self) -> u8 { self.0.month }

    pub fn day(&self) -> u8 { self.0.day }

    pub fn hour(&self) -> u8 { self.0.hour }

    pub fn minute(&self) -> u8 { self.0.minute }

    pub fn second(&self) -> u8 { self.0.second }

    pub fn write_time_choice(&self, raw_buffer: &mut [u8]) {
        use core::fmt::Write;
        let t = self.0;
        let mut buffer = super::buffer::FmtBuf::new(raw_buffer);
        if t.year > 2049 {
            write!(
                buffer,
                "\x18\x0f{:04}{:02}{:02}{:02}{:02}{:02}Z",
                t.year, t.month, t.day, t.hour, t.minute, t.second
            )
        } else {
            let year = if t.year > 2000 { t.year - 2000 } else { t.year - 1900 };
            write!(
                buffer,
                "\x17\x0d{:02}{:02}{:02}{:02}{:02}{:02}Z",
                year, t.month, t.day, t.hour, t.minute, t.second,
            )
        }
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    #[test]
    fn encodes_time_correctly() {
        const MIN_LONG_TIME: u64 = 2524608000;
        for i in 0..MAX_ASN1_TIMESTAMP / 86400 {
            let i = i * 86400;
            let tm = X509Time::try_from(i).unwrap();
            assert_eq!(tm.second(), 0);
            assert_eq!(tm.minute(), 0);
            assert_eq!(tm.hour(), 0);
            if i >= MIN_LONG_TIME {
                assert_eq!(tm.asn1_length(), 17);
            } else {
                assert_eq!(tm.asn1_length(), 15);
            }
            #[cfg(unix)]
            unsafe {
                if i > libc::time_t::max_value() as u64 {
                    continue
                }
                let mut t1: libc::tm = std::mem::zeroed();
                assert!(!libc::gmtime_r(&(i as libc::time_t), &mut t1).is_null());
                assert_eq!(t1.tm_sec, 0);
                assert_eq!(t1.tm_min, 0);
                assert_eq!(t1.tm_hour, 0);
                assert_eq!(t1.tm_year as i64, tm.year() - 1900);
                assert_eq!(t1.tm_mon, (tm.month() - 1).into());
                assert_eq!(t1.tm_mday, tm.day().try_into().unwrap());
            }
        }
    }
}
