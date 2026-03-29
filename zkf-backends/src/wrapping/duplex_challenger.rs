/// DuplexChallenger gadget: Poseidon2 duplex sponge in R1CS.
///
/// Matches `p3_challenger::DuplexChallenger<Goldilocks, Poseidon2Goldilocks<16>, 16, 8>`
/// exactly. The sponge state is 16 Goldilocks elements, with rate=8 and capacity=8.
///
/// Operations:
/// - `observe(element)`: absorb an element into the input buffer
/// - `sample()`: squeeze a challenge element from the output buffer
/// - `duplexing()`: flush the input buffer into sponge state, permute, refill output buffer
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::nonnative_goldilocks::GoldilocksVar;
use super::poseidon2_goldilocks::{POSEIDON2_WIDTH, Poseidon2GoldilocksGadget};

/// Rate of the duplex sponge (number of elements absorbed/squeezed per permutation).
const RATE: usize = 8;

/// Poseidon2 duplex challenger operating on GoldilocksVar elements in BN254 R1CS.
///
/// Mirrors the state machine of `p3_challenger::DuplexChallenger`:
/// - `sponge_state`: full permutation state (WIDTH=16 elements)
/// - `input_buffer`: pending elements to absorb (up to RATE=8)
/// - `output_buffer`: available squeezed elements (up to RATE=8)
pub struct DuplexChallengerGadget<'a> {
    poseidon2: &'a Poseidon2GoldilocksGadget,
    sponge_state: [GoldilocksVar; POSEIDON2_WIDTH],
    input_buffer: Vec<GoldilocksVar>,
    output_buffer: Vec<GoldilocksVar>,
}

impl<'a> DuplexChallengerGadget<'a> {
    /// Create a new challenger with zero-initialized sponge state.
    pub fn new(
        cs: ConstraintSystemRef<Fr>,
        poseidon2: &'a Poseidon2GoldilocksGadget,
    ) -> Result<Self, SynthesisError> {
        let sponge_state: [GoldilocksVar; POSEIDON2_WIDTH] =
            std::array::from_fn(|_| GoldilocksVar::constant(cs.clone(), 0).unwrap());
        Ok(Self {
            poseidon2,
            sponge_state,
            input_buffer: Vec::with_capacity(RATE),
            output_buffer: Vec::with_capacity(RATE),
        })
    }

    /// Observe (absorb) a single element into the challenger transcript.
    ///
    /// When the input buffer is full (RATE elements), triggers a duplexing call.
    pub fn observe(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        element: &GoldilocksVar,
    ) -> Result<(), SynthesisError> {
        // Observing clears the output buffer (matches p3-challenger behavior)
        self.output_buffer.clear();

        self.input_buffer.push(element.clone());
        if self.input_buffer.len() == RATE {
            self.duplexing(cs)?;
        }
        Ok(())
    }

    /// Observe a slice of elements.
    pub fn observe_slice(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        elements: &[GoldilocksVar],
    ) -> Result<(), SynthesisError> {
        for element in elements {
            self.observe(cs.clone(), element)?;
        }
        Ok(())
    }

    /// Sample (squeeze) a challenge element from the sponge.
    ///
    /// If the output buffer is empty, triggers a duplexing call first.
    pub fn sample(&mut self, cs: ConstraintSystemRef<Fr>) -> Result<GoldilocksVar, SynthesisError> {
        // If there are pending inputs or the output buffer is empty, duplex first
        if !self.input_buffer.is_empty() || self.output_buffer.is_empty() {
            self.duplexing(cs)?;
        }

        // Pop the last element from the output buffer (matches p3-challenger's .pop())
        Ok(self
            .output_buffer
            .pop()
            .expect("output_buffer should be non-empty after duplexing"))
    }

    /// Sample bits: advance the challenger state by sampling a field element.
    ///
    /// In the native DuplexChallenger, `sample_bits(bits)` samples a field element
    /// and masks to `bits` bits. For the circuit gadget, we just need to advance
    /// the state correctly (the PoW check is not verified in-circuit).
    pub fn sample_bits(
        &mut self,
        cs: ConstraintSystemRef<Fr>,
        _bits: usize,
    ) -> Result<GoldilocksVar, SynthesisError> {
        self.sample(cs)
    }

    /// Perform the duplex operation:
    /// 1. Absorb input_buffer into sponge_state[0..len] (overwrite only those positions)
    /// 2. Permute the full sponge state
    /// 3. Set output_buffer = sponge_state[0..RATE]
    /// 4. Clear input_buffer
    ///
    /// Matches p3-challenger exactly: does NOT zero-pad remaining rate positions.
    fn duplexing(&mut self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Absorb: overwrite only the first input_buffer.len() positions
        // (remaining state elements are preserved, matching p3-challenger)
        for (i, input) in self.input_buffer.drain(..).enumerate() {
            self.sponge_state[i] = input;
        }

        // Permute the full sponge state
        self.poseidon2.permute(cs, &mut self.sponge_state)?;

        // Squeeze: set output buffer to the rate portion of the state
        self.output_buffer.clear();
        self.output_buffer
            .extend_from_slice(&self.sponge_state[0..RATE]);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use p3_challenger::{CanObserve, CanSample};
    use p3_field::PrimeCharacteristicRing;
    use p3_field::PrimeField64;
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use rand09::SeedableRng;
    use rand09::rngs::SmallRng;

    /// Build a native DuplexChallenger matching the gadget's configuration.
    fn native_challenger(
        seed: u64,
    ) -> p3_challenger::DuplexChallenger<Goldilocks, Poseidon2Goldilocks<16>, 16, 8> {
        let mut rng = SmallRng::seed_from_u64(seed);
        let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
        p3_challenger::DuplexChallenger::new(perm)
    }

    #[test]
    fn duplex_challenger_observe_sample_matches_native() {
        let seed = 42u64;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon2 = Poseidon2GoldilocksGadget::new(seed);

        // Build both challengers
        let mut native = native_challenger(seed);
        let mut gadget = DuplexChallengerGadget::new(cs.clone(), &poseidon2).unwrap();

        // Observe the same sequence of elements
        let test_values: Vec<u64> = vec![1, 2, 3, 4, 5];
        for &v in &test_values {
            native.observe(Goldilocks::from_u64(v));
            let gv = GoldilocksVar::alloc_witness(cs.clone(), Some(v)).unwrap();
            gadget.observe(cs.clone(), &gv).unwrap();
        }

        // Sample and compare
        let native_sample: Goldilocks = native.sample();
        let gadget_sample = gadget.sample(cs.clone()).unwrap();

        assert_eq!(
            gadget_sample.value().unwrap(),
            native_sample.as_canonical_u64(),
            "DuplexChallenger gadget sample must match native"
        );
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn duplex_challenger_multiple_samples_match_native() {
        let seed = 42u64;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon2 = Poseidon2GoldilocksGadget::new(seed);

        let mut native = native_challenger(seed);
        let mut gadget = DuplexChallengerGadget::new(cs.clone(), &poseidon2).unwrap();

        // Observe 10 elements (triggers at least one duplexing)
        for v in 0..10u64 {
            native.observe(Goldilocks::from_u64(v));
            let gv = GoldilocksVar::alloc_witness(cs.clone(), Some(v)).unwrap();
            gadget.observe(cs.clone(), &gv).unwrap();
        }

        // Sample multiple times
        for i in 0..4 {
            let ns: Goldilocks = native.sample();
            let gs = gadget.sample(cs.clone()).unwrap();
            assert_eq!(
                gs.value().unwrap(),
                ns.as_canonical_u64(),
                "Sample {i} mismatch"
            );
        }

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn duplex_challenger_interleaved_observe_sample() {
        let seed = 42u64;
        let cs = ConstraintSystem::<Fr>::new_ref();
        let poseidon2 = Poseidon2GoldilocksGadget::new(seed);

        let mut native = native_challenger(seed);
        let mut gadget = DuplexChallengerGadget::new(cs.clone(), &poseidon2).unwrap();

        // Observe 3 elements
        for v in [100u64, 200, 300] {
            native.observe(Goldilocks::from_u64(v));
            let gv = GoldilocksVar::alloc_witness(cs.clone(), Some(v)).unwrap();
            gadget.observe(cs.clone(), &gv).unwrap();
        }

        // Sample 1
        let ns1: Goldilocks = native.sample();
        let gs1 = gadget.sample(cs.clone()).unwrap();
        assert_eq!(gs1.value().unwrap(), ns1.as_canonical_u64());

        // Observe 2 more
        for v in [400u64, 500] {
            native.observe(Goldilocks::from_u64(v));
            let gv = GoldilocksVar::alloc_witness(cs.clone(), Some(v)).unwrap();
            gadget.observe(cs.clone(), &gv).unwrap();
        }

        // Sample 2
        let ns2: Goldilocks = native.sample();
        let gs2 = gadget.sample(cs.clone()).unwrap();
        assert_eq!(gs2.value().unwrap(), ns2.as_canonical_u64());

        assert!(cs.is_satisfied().unwrap());
    }
}
