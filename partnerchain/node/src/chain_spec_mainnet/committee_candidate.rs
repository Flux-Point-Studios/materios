//! The committee candidate validator a partner chain's genesis UTXO
//! parameterises, whose address the follower reads registrations at.
//!
//! partner-chains v1.8.0, which sets the chain up on Cardano, applies the
//! validator to the genesis UTXO as aiken's `uplc` applies Plutus data to a
//! program, and hashes the applied script as a Plutus V2 script.

use hex_literal::hex;

/// `COMMITTEE_CANDIDATE_VALIDATOR` of partner-chains-smart-contracts v8.1.0
/// (`raw-scripts/src/lib.rs`), the release partner-chains v1.8.0 pins: a CBOR
/// byte string holding a flat-encoded UPLC program.
const COMMITTEE_CANDIDATE_VALIDATOR: [u8; 177] = hex!(
    "58af0100002222533533223535323233322212333001004003002375c6ae84008d5d08009bad357426ae88004d"
    "5d10009bac005222123330010040030022322253355335300337586ae84d5d11aba2357446ae88d5d11aba2357"
    "446ae88d55cf1baa357426aae78dd500390803880288030802991800800912999aab9f00111220011325335333"
    "573466e3c0100040180144488c00800c4c8cc010010004d5d10011bae357420022440042440022930b01"
);

/// The script hash of the committee candidate validator of the partner chain
/// whose genesis UTXO is `tx_hash#index`.
pub fn validator_hash(tx_hash: &[u8; 32], index: u16) -> Result<[u8; 28], String> {
    let applied = apply_data(&COMMITTEE_CANDIDATE_VALIDATOR, &utxo_data(tx_hash, index))?;
    let hash = blake2b_simd::Params::new()
        .hash_length(28)
        .to_state()
        .update(&[PLUTUS_V2])
        .update(&applied)
        .finalize();
    hash.as_bytes()
        .try_into()
        .map_err(|_| "blake2b-224 gave no 28 bytes".to_string())
}

/// The language tag a Plutus V2 script's hash covers before the script.
const PLUTUS_V2: u8 = 2;

/// The UTXO as Plutus data, `Constr 0 [Constr 0 [tx_hash], index]`, in the
/// CBOR partner-chains writes a script parameter in: each non-empty list of
/// fields of indefinite length.
fn utxo_data(tx_hash: &[u8; 32], index: u16) -> Vec<u8> {
    const CONSTR_0_FIELDS: [u8; 3] = [0xd8, 0x79, 0x9f];
    const BREAK: u8 = 0xff;
    let mut data = Vec::with_capacity(48);
    data.extend(CONSTR_0_FIELDS);
    data.extend(CONSTR_0_FIELDS);
    data.extend(cbor_head(BYTES, 32));
    data.extend(tx_hash);
    data.push(BREAK);
    data.extend(cbor_head(UNSIGNED, index.into()));
    data.push(BREAK);
    data
}

const UNSIGNED: u8 = 0;
const BYTES: u8 = 2;

fn cbor_head(major: u8, n: u64) -> Vec<u8> {
    let major = major << 5;
    match n {
        0..=23 => vec![major | n as u8],
        24..=0xff => vec![major | 24, n as u8],
        0x100..=0xffff => [vec![major | 25], (n as u16).to_be_bytes().to_vec()].concat(),
        0x1_0000..=0xffff_ffff => [vec![major | 26], (n as u32).to_be_bytes().to_vec()].concat(),
        _ => [vec![major | 27], n.to_be_bytes().to_vec()].concat(),
    }
}

/// The bytes a CBOR byte string holds, which must be all of `cbor`.
fn cbor_bytes(cbor: &[u8]) -> Result<&[u8], String> {
    let (length, start) = match cbor {
        [head @ 0x40..=0x57, ..] => (usize::from(head & 0x1f), 1),
        [0x58, n, ..] => (usize::from(*n), 2),
        [0x59, a, b, ..] => (usize::from(u16::from_be_bytes([*a, *b])), 3),
        _ => return Err("the script is not a CBOR byte string".to_string()),
    };
    if cbor.len() != start + length {
        return Err("the script's CBOR byte string is not the whole script".to_string());
    }
    Ok(&cbor[start..])
}

/// `script`, a CBOR byte string holding a flat-encoded program, applied to the
/// Plutus data `data`: the program `[term (con data data)]` with the script's
/// version, flat-encoded and in a CBOR byte string again.
fn apply_data(script: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let program = cbor_bytes(script)?;
    let mut flat = Flat::new(program);
    for _ in 0..3 {
        flat.copy_word()?;
    }
    flat.put(APPLY, TERM_TAG_BITS);
    flat.copy_term()?;
    flat.skip_filler()?;
    if flat.read != 8 * program.len() {
        return Err("the program goes on after its term".to_string());
    }
    flat.put(CONSTANT, TERM_TAG_BITS);
    flat.put(1, 1);
    flat.put(DATA, TYPE_TAG_BITS);
    flat.put(0, 1);
    flat.put_bytes(data);
    flat.put_filler();
    let mut applied = cbor_head(BYTES, flat.out.len() as u64);
    applied.extend(flat.out);
    Ok(applied)
}

const TERM_TAG_BITS: u32 = 4;
const TYPE_TAG_BITS: u32 = 4;
const BUILTIN_BITS: u32 = 7;
const APPLY: u64 = 3;
const CONSTANT: u64 = 4;
const DATA: u64 = 8;

const UNREADABLE_APPLICATION: &str = "the script holds a type application it cannot read";

/// A constant's type, as its flat list of type tags spells it.
enum Type {
    Integer,
    Bytes,
    Unit,
    Bool,
    List(Box<Type>),
    Pair(Box<Type>, Box<Type>),
}

impl Type {
    fn read(tags: &mut impl Iterator<Item = u64>) -> Result<Type, String> {
        Ok(match tags.next() {
            Some(0) => Type::Integer,
            Some(1 | 2 | 8) => Type::Bytes,
            Some(3) => Type::Unit,
            Some(4) => Type::Bool,
            Some(7) => match tags.next() {
                Some(5) => Type::List(Box::new(Type::read(tags)?)),
                Some(7) => match tags.next() {
                    Some(6) => Type::Pair(Box::new(Type::read(tags)?), Box::new(Type::read(tags)?)),
                    _ => return Err(UNREADABLE_APPLICATION.to_string()),
                },
                _ => return Err(UNREADABLE_APPLICATION.to_string()),
            },
            _ => return Err("the script holds a constant type it cannot read".to_string()),
        })
    }
}

/// A flat-encoded program read bit by bit and copied, shifted, to `out`.
struct Flat<'a> {
    input: &'a [u8],
    read: usize,
    out: Vec<u8>,
    written: usize,
}

impl<'a> Flat<'a> {
    fn new(input: &'a [u8]) -> Self {
        Flat {
            input,
            read: 0,
            out: Vec::with_capacity(input.len() + 64),
            written: 0,
        }
    }

    fn take(&mut self, bits: u32) -> Result<u64, String> {
        let mut value = 0;
        for _ in 0..bits {
            let byte = self
                .input
                .get(self.read / 8)
                .ok_or("the program ends early")?;
            value = value << 1 | u64::from(byte >> (7 - self.read % 8) & 1);
            self.read += 1;
        }
        Ok(value)
    }

    fn put(&mut self, value: u64, bits: u32) {
        for bit in (0..bits).rev() {
            if self.written % 8 == 0 {
                self.out.push(0);
            }
            if value >> bit & 1 == 1 {
                let at = self.written / 8;
                self.out[at] |= 0x80 >> (self.written % 8);
            }
            self.written += 1;
        }
    }

    fn copy(&mut self, bits: u32) -> Result<u64, String> {
        let value = self.take(bits)?;
        self.put(value, bits);
        Ok(value)
    }

    /// A natural: 7 bits a byte, each byte's top bit saying another follows.
    fn copy_word(&mut self) -> Result<(), String> {
        while self.copy(8)? & 0x80 != 0 {}
        Ok(())
    }

    /// Zero bits and a one up to a byte boundary.
    fn skip_filler(&mut self) -> Result<(), String> {
        while self.take(1)? == 0 {}
        if self.read % 8 != 0 {
            return Err("the program's filler ends off a byte boundary".to_string());
        }
        Ok(())
    }

    fn put_filler(&mut self) {
        while self.written % 8 != 7 {
            self.put(0, 1);
        }
        self.put(1, 1);
    }

    /// A byte string: aligned by a filler, which moves with where the string
    /// starts, then chunks of at most 255 bytes, each after its length, and
    /// an empty chunk.
    fn copy_bytes(&mut self) -> Result<(), String> {
        self.skip_filler()?;
        self.put_filler();
        loop {
            let length = self.copy(8)?;
            if length == 0 {
                return Ok(());
            }
            for _ in 0..length {
                self.copy(8)?;
            }
        }
    }

    fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_filler();
        for chunk in bytes.chunks(255) {
            self.put(chunk.len() as u64, 8);
            for byte in chunk {
                self.put(u64::from(*byte), 8);
            }
        }
        self.put(0, 8);
    }

    fn copy_value(&mut self, of: &Type) -> Result<(), String> {
        match of {
            Type::Integer => self.copy_word(),
            Type::Bytes => self.copy_bytes(),
            Type::Unit => Ok(()),
            Type::Bool => self.copy(1).map(drop),
            Type::List(item) => {
                while self.copy(1)? == 1 {
                    self.copy_value(item)?;
                }
                Ok(())
            }
            Type::Pair(first, second) => {
                self.copy_value(first)?;
                self.copy_value(second)
            }
        }
    }

    /// One term with its subterms: a variable, delay, lambda, application,
    /// constant, force, error or builtin. The scripts are UPLC 1.0, which has
    /// no constr or case.
    fn copy_term(&mut self) -> Result<(), String> {
        let mut pending = 1u32;
        while pending > 0 {
            pending -= 1;
            match self.copy(TERM_TAG_BITS)? {
                0 => self.copy_word()?,
                1 | 2 | 5 => pending += 1,
                APPLY => pending += 2,
                CONSTANT => {
                    let mut tags = Vec::new();
                    while self.copy(1)? == 1 {
                        tags.push(self.copy(TYPE_TAG_BITS)?);
                    }
                    let mut tags = tags.into_iter();
                    let of = Type::read(&mut tags)?;
                    if tags.next().is_some() {
                        return Err("a constant's type list goes on after its type".to_string());
                    }
                    self.copy_value(&of)?;
                }
                6 => {}
                7 => {
                    self.copy(BUILTIN_BITS)?;
                }
                tag => return Err(format!("the program holds term tag {tag}, not UPLC 1.0")),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bech32_payload(text: &str) -> Vec<u8> {
        use bech32::FromBase32;
        let (_, data) = bech32::decode(text).expect("bech32");
        Vec::<u8>::from_base32(&data).expect("whole bytes")
    }

    fn utxo(text: &str) -> ([u8; 32], u16) {
        let (tx, index) = text.split_once('#').expect("tx#index");
        let tx = sp_core::bytes::from_hex(tx).expect("hex");
        (
            tx.try_into().expect("32 bytes"),
            index.parse().expect("an index"),
        )
    }

    /// Preprod was set up with partner-chains v1.8.0, and its nodes read
    /// registrations at the address its genesis stores: the validator of its
    /// genesis UTXO, on the test network (header 0x70).
    #[test]
    fn the_validator_of_preprods_genesis_utxo_is_at_the_address_preprods_genesis_stores() {
        let preprod = crate::chain_spec_preprod::genesis_patch();
        let (tx, index) = utxo(preprod["sidechain"]["genesisUtxo"].as_str().unwrap());
        let stored = preprod["sessionCommitteeManagement"]["mainChainScripts"]
            ["committee_candidate_address"]
            .as_str()
            .unwrap();
        let text = String::from_utf8(sp_core::bytes::from_hex(stored).unwrap()).unwrap();
        let hash = validator_hash(&tx, index).unwrap();
        assert_eq!(
            hash,
            hex!("fed2f2fdc87b0a9d6e91220cb2788107793413b094e172a414b0a05c")
        );
        assert_eq!(bech32_payload(&text), [&[0x70], &hash[..]].concat());
    }

    #[test]
    fn each_genesis_utxo_parameterises_a_validator_of_its_own() {
        let (tx, index) =
            utxo("13313ea0119e0c4330f64f1809159064a371a1bbf2050b1fe13d5492280dca50#0");
        let mut other_tx = tx;
        other_tx[31] ^= 1;
        let hashes = [
            validator_hash(&tx, index).unwrap(),
            validator_hash(&tx, 1).unwrap(),
            validator_hash(&tx, 300).unwrap(),
            validator_hash(&tx, 32767).unwrap(),
            validator_hash(&other_tx, index).unwrap(),
        ];
        let distinct: std::collections::BTreeSet<_> = hashes.iter().collect();
        assert_eq!(distinct.len(), hashes.len());
    }

    #[test]
    fn the_utxo_is_the_plutus_data_partner_chains_writes() {
        let data = utxo_data(&[0xab; 32], 300);
        assert_eq!(
            sp_core::bytes::to_hex(&data, false),
            format!("0xd8799fd8799f5820{}ff19012cff", "ab".repeat(32))
        );
        assert_eq!(utxo_data(&[0xab; 32], 0)[41..], [0x00, 0xff]);
        assert_eq!(utxo_data(&[0xab; 32], 24)[41..], [0x18, 0x18, 0xff]);
    }

    #[test]
    fn a_script_that_is_not_one_whole_cbor_byte_string_is_refused() {
        let mut longer = COMMITTEE_CANDIDATE_VALIDATOR.to_vec();
        longer.push(0);
        let mut truncated = COMMITTEE_CANDIDATE_VALIDATOR.to_vec();
        truncated[1] += 1;
        truncated.push(0);
        for script in [
            &longer[..],
            &truncated[..],
            &COMMITTEE_CANDIDATE_VALIDATOR[1..],
        ] {
            assert!(apply_data(script, &[0]).is_err());
        }
    }
}
