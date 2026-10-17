use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Account([u8; 32]),
    Utxo([u8; 32]),
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidRecipient;

pub fn encode(recipient: Recipient) -> Vec<u8> {
    let (prefix, key): (&[u8], _) = match recipient {
        Recipient::Account(key) => (&[0x82, 1, 0x82, 0, 0x58, 32], key),
        Recipient::Utxo(key) => (&[0x82, 1, 0x82, 1, 0x82, 0, 0x58, 32], key),
    };
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&key);
    bytes
}

pub fn decode(bytes: &[u8]) -> Result<Recipient, InvalidRecipient> {
    if bytes.len() == 38 && bytes.starts_with(&[0x82, 1, 0x82, 0, 0x58, 32]) {
        Ok(Recipient::Account(
            bytes[6..].try_into().map_err(|_| InvalidRecipient)?,
        ))
    } else if bytes.len() == 40 && bytes.starts_with(&[0x82, 1, 0x82, 1, 0x82, 0, 0x58, 32]) {
        Ok(Recipient::Utxo(
            bytes[8..].try_into().map_err(|_| InvalidRecipient)?,
        ))
    } else {
        Err(InvalidRecipient)
    }
}
