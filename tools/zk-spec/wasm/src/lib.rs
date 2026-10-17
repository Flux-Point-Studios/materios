#![no_std]
extern crate alloc;
use lol_alloc::{FreeListAllocator, LockedAllocator};
use materios_zk_core::sapling::{Bundle, InvalidEncoding, Verifier};

#[global_allocator]
static ALLOCATOR: LockedAllocator<FreeListAllocator> =
    LockedAllocator::new(FreeListAllocator::new());

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

lazy_static::lazy_static! {
    static ref VERIFIER: Result<Verifier, InvalidEncoding> = Verifier::new(
        SPEND_KEY, OUTPUT_KEY);
}

const SPEND_KEY: &[u8] = include_bytes!("../../fixtures/sapling-spend.vk");
const OUTPUT_KEY: &[u8] = include_bytes!("../../fixtures/sapling-output.vk");

#[no_mangle]
pub extern "C" fn zk_init() -> u32 {
    u32::from(VERIFIER.is_ok())
}

#[no_mangle]
pub extern "C" fn zk_vector(index: u32, bit: i32) -> u32 {
    let Ok(verifier) = &*VERIFIER else {
        return 0;
    };
    let mut bytes: &[u8] = include_bytes!("../../fixtures/actions.bin");
    for n in 0..=index {
        let Some(kind) = bytes.first() else {
            return 0;
        };
        let spend = *kind == 1;
        let len = if spend { 384 } else { 948 };
        if bytes.len() < len + 1 {
            return 0;
        }
        if n == index {
            let mut action = bytes[1..len + 1].to_vec();
            if bit >= 0 {
                if bit >= 1536 {
                    return 0;
                }
                action[(if spend { 128 } else { 756 }) + bit as usize / 8] ^= 1 << (bit % 8);
            }
            return u32::from(verifier.proof(spend, &action));
        }
        bytes = &bytes[len + 1..];
    }
    0
}

#[no_mangle]
pub extern "C" fn zk_bundle(index: u32, mutation: u32) -> u32 {
    let Ok(verifier) = Verifier::new(SPEND_KEY, OUTPUT_KEY) else {
        return 0;
    };
    let mut bytes: &[u8] = include_bytes!("../../fixtures/bundles.bin");
    for n in 0..=index {
        let Ok(size): Result<[u8; 4], _> = bytes.get(..4).unwrap_or(&[]).try_into() else {
            return 0;
        };
        let size = u32::from_le_bytes(size) as usize;
        let Some(raw) = bytes.get(4..4 + size) else {
            return 0;
        };
        if n == index {
            let mut encoded = raw.to_vec();
            match mutation {
                0 => (),
                1 => {
                    let end = encoded.len() - 1;
                    encoded[end] ^= 1;
                }
                2 => encoded[0] ^= 1,
                3 => {
                    encoded.pop();
                }
                _ => return 0,
            }
            let Ok(bundle) = Bundle::decode(&encoded) else {
                return 0;
            };
            return u32::from(verifier.bundle(
                &bundle.spends,
                &bundle.outputs,
                bundle.balance,
                bundle.sighash,
                bundle.binding,
            ));
        }
        bytes = &bytes[4 + size..];
    }
    0
}
