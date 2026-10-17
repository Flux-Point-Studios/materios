#[derive(Debug, PartialEq, Eq)]
pub struct MainnetDenied;

pub fn enable(source_route: &str, chain_id: &str) -> Result<(), MainnetDenied> {
    match (source_route, chain_id) {
        ("dev", "materios_dev")
        | ("local", "materios_local")
        | ("preprod", "materios_preprod_v6") => Ok(()),
        _ => Err(MainnetDenied),
    }
}
