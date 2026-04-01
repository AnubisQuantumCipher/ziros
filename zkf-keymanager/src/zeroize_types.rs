use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Ed25519Seed(pub [u8; 32]);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsa87PrivateKey(pub Vec<u8>);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlKem1024DecapsulationKey(pub Vec<u8>);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct X25519Secret(pub [u8; 32]);

#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrappers_zeroize_on_drop_trait_bounds_compile() {
        fn assert_zeroize<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize::<Ed25519Seed>();
        assert_zeroize::<MlDsa87PrivateKey>();
        assert_zeroize::<MlKem1024DecapsulationKey>();
        assert_zeroize::<X25519Secret>();
        assert_zeroize::<SymmetricKey>();
    }
}
