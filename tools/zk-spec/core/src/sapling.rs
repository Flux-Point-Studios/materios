use alloc::{vec, vec::Vec};
use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use group::{Curve, GroupEncoding};
use redjubjub::{Binding, SpendAuth, VerificationKey};
use sapling_crypto::{
    value::{CommitmentSum, ValueCommitment},
    CommitmentTree, Node,
};

#[derive(Debug)]
pub struct InvalidEncoding;

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], InvalidEncoding> {
    bytes.try_into().map_err(|_| InvalidEncoding)
}

fn g1(bytes: &[u8], compressed: bool) -> Result<G1Affine, InvalidEncoding> {
    let point = if compressed {
        Option::<bls12_381::G1Affine>::from(bls12_381::G1Affine::from_compressed(&array(bytes)?))
    } else {
        Option::<bls12_381::G1Affine>::from(bls12_381::G1Affine::from_uncompressed(&array(bytes)?))
    }
    .ok_or(InvalidEncoding)?;
    if bool::from(point.is_identity()) {
        return Err(InvalidEncoding);
    }
    let raw = point.to_uncompressed();
    Ok(G1Affine::new_unchecked(
        Fq::from_be_bytes_mod_order(&raw[..48]),
        Fq::from_be_bytes_mod_order(&raw[48..]),
    ))
}

fn g2(bytes: &[u8], compressed: bool) -> Result<G2Affine, InvalidEncoding> {
    let point = if compressed {
        Option::<bls12_381::G2Affine>::from(bls12_381::G2Affine::from_compressed(&array(bytes)?))
    } else {
        Option::<bls12_381::G2Affine>::from(bls12_381::G2Affine::from_uncompressed(&array(bytes)?))
    }
    .ok_or(InvalidEncoding)?;
    if bool::from(point.is_identity()) {
        return Err(InvalidEncoding);
    }
    let raw = point.to_uncompressed();
    Ok(G2Affine::new_unchecked(
        Fq2::new(
            Fq::from_be_bytes_mod_order(&raw[48..96]),
            Fq::from_be_bytes_mod_order(&raw[..48]),
        ),
        Fq2::new(
            Fq::from_be_bytes_mod_order(&raw[144..]),
            Fq::from_be_bytes_mod_order(&raw[96..144]),
        ),
    ))
}

fn key(bytes: &[u8], inputs: usize) -> Result<PreparedVerifyingKey<Bls12_381>, InvalidEncoding> {
    if bytes.len() != 868 + (inputs + 1) * 96
        || u32::from_be_bytes(array(&bytes[864..868])?) as usize != inputs + 1
    {
        return Err(InvalidEncoding);
    }
    let vk = VerifyingKey {
        alpha_g1: g1(&bytes[..96], false)?,
        beta_g2: g2(&bytes[192..384], false)?,
        gamma_g2: g2(&bytes[384..576], false)?,
        delta_g2: g2(&bytes[672..864], false)?,
        gamma_abc_g1: bytes[868..]
            .chunks_exact(96)
            .map(|p| g1(p, false))
            .collect::<Result<_, _>>()?,
    };
    let _ = g1(&bytes[96..192], false)?;
    let _ = g1(&bytes[576..672], false)?;
    Ok(prepare_verifying_key(&vk))
}

fn scalar(bytes: &[u8]) -> Result<Fr, InvalidEncoding> {
    Option::<bls12_381::Scalar>::from(bls12_381::Scalar::from_bytes(&array(bytes)?))
        .ok_or(InvalidEncoding)?;
    Ok(Fr::from_le_bytes_mod_order(bytes))
}

fn point_inputs(bytes: &[u8]) -> Result<[Fr; 2], InvalidEncoding> {
    let point =
        Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&array(bytes)?))
            .ok_or(InvalidEncoding)?;
    if bool::from(point.is_small_order()) {
        return Err(InvalidEncoding);
    }
    let affine = point.to_affine();
    Ok([
        scalar(&affine.get_u().to_bytes())?,
        scalar(&affine.get_v().to_bytes())?,
    ])
}

pub struct Verifier {
    spend: PreparedVerifyingKey<Bls12_381>,
    output: PreparedVerifyingKey<Bls12_381>,
}

impl Verifier {
    pub fn new(spend: &[u8], output: &[u8]) -> Result<Self, InvalidEncoding> {
        Ok(Self {
            spend: key(spend, 7)?,
            output: key(output, 5)?,
        })
    }

    pub fn proof(&self, spend: bool, action: &[u8]) -> bool {
        self.proof_checked(spend, action).is_ok()
    }

    fn proof_checked(&self, spend: bool, action: &[u8]) -> Result<(), InvalidEncoding> {
        if action.len() != if spend { 384 } else { 948 } {
            return Err(InvalidEncoding);
        }
        let (vk, bytes, inputs) = if spend {
            let rk = point_inputs(&action[96..128])?;
            let cv = point_inputs(&action[..32])?;
            let mut nf: [u8; 32] = array(&action[64..96])?;
            let high = nf[31] >> 6;
            nf[31] &= 0x3f;
            (
                &self.spend,
                &action[128..320],
                vec![
                    rk[0],
                    rk[1],
                    cv[0],
                    cv[1],
                    scalar(&action[32..64])?,
                    Fr::from_le_bytes_mod_order(&nf),
                    Fr::from(high),
                ],
            )
        } else {
            let cv = point_inputs(&action[..32])?;
            let epk = point_inputs(&action[64..96])?;
            (
                &self.output,
                &action[756..948],
                vec![cv[0], cv[1], epk[0], epk[1], scalar(&action[32..64])?],
            )
        };
        let proof = Proof {
            a: g1(&bytes[..48], true)?,
            b: g2(&bytes[48..144], true)?,
            c: g1(&bytes[144..], true)?,
        };
        if Groth16::<Bls12_381>::verify_proof(vk, &proof, &inputs).map_err(|_| InvalidEncoding)? {
            Ok(())
        } else {
            Err(InvalidEncoding)
        }
    }

    pub fn bundle(
        &self,
        spends: &[&[u8]],
        outputs: &[&[u8]],
        balance: i64,
        sighash: &[u8],
        binding: &[u8],
    ) -> bool {
        self.bundle_checked(spends, outputs, balance, sighash, binding)
            .is_ok()
    }

    fn bundle_checked(
        &self,
        spends: &[&[u8]],
        outputs: &[&[u8]],
        balance: i64,
        sighash: &[u8],
        binding: &[u8],
    ) -> Result<(), InvalidEncoding> {
        if sighash.len() != 32 || spends.len() != 1 || outputs.len() != 2 {
            return Err(InvalidEncoding);
        }
        let mut sum = CommitmentSum::zero();
        let mut tree = CommitmentTree::empty();
        for spend in spends {
            self.proof_checked(true, spend)?;
            let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(
                &array(&spend[..32])?,
            ))
            .ok_or(InvalidEncoding)?;
            sum += &cv;
            let rk = VerificationKey::<SpendAuth>::try_from(array::<32>(&spend[96..128])?)
                .map_err(|_| InvalidEncoding)?;
            rk.verify(sighash, &array::<64>(&spend[320..])?.into())
                .map_err(|_| InvalidEncoding)?;
        }
        for output in outputs {
            self.proof_checked(false, output)?;
            let cv = Option::<ValueCommitment>::from(ValueCommitment::from_bytes_not_small_order(
                &array(&output[..32])?,
            ))
            .ok_or(InvalidEncoding)?;
            sum -= &cv;
            let node = Option::<Node>::from(Node::from_bytes(array(&output[32..64])?))
                .ok_or(InvalidEncoding)?;
            tree.append(node).map_err(|_| InvalidEncoding)?;
        }
        core::hint::black_box(tree.root().to_bytes());
        let bvk: VerificationKey<Binding> = sum.into_bvk(balance);
        bvk.verify(sighash, &array::<64>(binding)?.into())
            .map_err(|_| InvalidEncoding)
    }
}

pub struct Bundle<'a> {
    pub sighash: &'a [u8],
    pub balance: i64,
    pub spends: Vec<&'a [u8]>,
    pub outputs: Vec<&'a [u8]>,
    pub binding: &'a [u8],
}

impl<'a> Bundle<'a> {
    pub fn decode(mut bytes: &'a [u8]) -> Result<Self, InvalidEncoding> {
        fn take<'a>(bytes: &mut &'a [u8], n: usize) -> Result<&'a [u8], InvalidEncoding> {
            if bytes.len() < n {
                return Err(InvalidEncoding);
            }
            let (head, tail) = bytes.split_at(n);
            *bytes = tail;
            Ok(head)
        }
        let sighash = take(&mut bytes, 32)?;
        let balance = i64::from_le_bytes(array(take(&mut bytes, 8)?)?);
        let mut actions = |size| -> Result<Vec<&'a [u8]>, InvalidEncoding> {
            let count = u32::from_le_bytes(array(take(&mut bytes, 4)?)?) as usize;
            if count > 64 {
                return Err(InvalidEncoding);
            }
            (0..count).map(|_| take(&mut bytes, size)).collect()
        };
        let spends = actions(384)?;
        let outputs = actions(948)?;
        let binding = take(&mut bytes, 64)?;
        if !bytes.is_empty() {
            return Err(InvalidEncoding);
        }
        Ok(Self {
            sighash,
            balance,
            spends,
            outputs,
            binding,
        })
    }
}
