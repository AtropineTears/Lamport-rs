use getrandom;

/// Internal OS Randomness For 32-bytes using `getrandom` crate
/// 
/// This is the only one that implements copy and can be kept on the stack as the array only has 32 elements.
pub fn random_32() -> [u8;32]{
    return get_random_buf().unwrap()
}
/// Internal OS Randomness For 48-bytes using `getrandom` crate
pub fn random_48() -> [u8;48]{
    return get_random_buf_48().unwrap()
}
/// Internal OS Randomness For 64-bytes using `getrandom` crate
pub fn random_64() -> [u8;64]{
    return get_random_buf_64().unwrap()
}
/// Internal OS Randomness For 128-bytes using `getrandom` crate
pub fn random_128() -> [u8;128]{
    return get_random_buf_128().unwrap()
}

fn get_random_buf() -> Result<[u8; 32], getrandom::Error> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
fn get_random_buf_48() -> Result<[u8; 48], getrandom::Error> {
    let mut buf = [0u8; 48];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
fn get_random_buf_64() -> Result<[u8; 64], getrandom::Error> {
    let mut buf = [0u8; 64];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
fn get_random_buf_128() -> Result<[u8; 128], getrandom::Error> {
    let mut buf = [0u8; 128];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}