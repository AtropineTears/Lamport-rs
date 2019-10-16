pub fn random_32() -> Result<[u8; 32], getrandom::Error> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
pub fn random_48() -> Result<[u8; 48], getrandom::Error> {
    let mut buf = [0u8; 48];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
pub fn random_64() -> Result<[u8; 64], getrandom::Error> {
    let mut buf = [0u8; 64];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}