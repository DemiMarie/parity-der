#![cfg(any())]
use libc::time_t;
extern "C" {
    fn time(ptr: *mut time_t) -> time_t;
}
fn main() {
    let now = Utc::now();
    if now.year() > 2049 {
        println!("Time is {}", now.format("\x18\x0f%Y%m%d%H%M%SZ"));
    } else {
        let now = now.format("\x17\x0d%y%m%d%H%M%SZ");
        assert_eq!(now.len(), 13);
        println!("Time is {}", now);
    }
}
