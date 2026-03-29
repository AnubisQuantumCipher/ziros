#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
#![allow(dead_code)]

use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
use zkf_core::{
    BlackBoxOp, Expr, FieldElement, FieldId, PublicKeyBundle, SignatureBundle, SignatureScheme,
    Witness, WitnessInputs, bundle_has_required_signature_material, mod_inverse_bigint,
    normalize_mod, verify_bundle,
};
use zkf_core::{ZkfError, ZkfResult};

use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REENTRY_APP_FIELD: FieldId = FieldId::Goldilocks;
const REENTRY_FIXED_POINT_DECIMALS: u32 = 6;
pub const REENTRY_ASSURANCE_ML_DSA_CONTEXT: &[u8] = b"zkf-reentry-assurance-v1";

pub const PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS: usize = 256;
pub const PRIVATE_REENTRY_THERMAL_PER_STEP_INPUTS: usize = 4; // bank_cos, sin_gamma, cos_gamma, rho
pub const PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS: usize = 8; // h0, V0, gamma0, mass, S_ref, C_D, C_L, r_n
pub const PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS: usize = 7; // q_max, q_dot_max, h_min, v_max, gamma_bound, g_0, k_sg
pub const PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS: usize = 5; // trajectory_commitment, terminal_state_commitment, constraint_satisfaction, peak_q, peak_q_dot

const PRIVATE_REENTRY_THERMAL_DESCRIPTION: &str = "Propagate a private reusable launch vehicle reentry mission pack over a fixed reduced-order horizon using normalized kilometer / kilometer-per-second units, enforce thermal-safety and flight-envelope constraints per step, and expose theorem-first trajectory commitments plus a fail-closed compliance certificate, peak dynamic pressure, and peak heating rate.";
const PRIVATE_REENTRY_THERMAL_TEST_HELPER_DESCRIPTION: &str = "Doc-hidden arbitrary-step helper for in-repo testing and exporter regression of the theorem-first private reentry thermal-assurance surface. The shipped theorem-first surface remains fixed to the 256-step profile.";
const STACK_GROW_RED_ZONE: usize = 1024 * 1024;
const STACK_GROW_SIZE: usize = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Request / Response structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateReentryThermalRequestV1 {
    pub private: ReentryPrivateInputsV1,
    pub public: ReentryPublicInputsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryPrivateInputsV1 {
    pub initial_altitude: String,
    pub initial_velocity: String,
    pub initial_flight_path_angle: String,
    pub vehicle_mass: String,
    pub reference_area: String,
    pub drag_coefficient: String,
    pub lift_coefficient: String,
    pub nose_radius: String,
    pub bank_angle_cosines: Vec<String>,
    pub sin_gamma: Vec<String>,
    pub cos_gamma: Vec<String>,
    pub density_profile: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryPublicInputsV1 {
    pub q_max: String,
    pub q_dot_max: String,
    pub h_min: String,
    pub v_max: String,
    pub gamma_bound: String,
    pub g_0: String,
    pub k_sg: String,
    pub step_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryPublicEnvelopeV1 {
    pub q_max: String,
    pub q_dot_max: String,
    pub h_min: String,
    pub v_max: String,
    pub gamma_bound: String,
    pub g_0: String,
    pub k_sg: String,
    pub certified_horizon_steps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryPrivateModelCommitmentsV1 {
    pub mission_id: String,
    pub aerodynamic_model_commitment: String,
    pub thermal_model_commitment: String,
    pub guidance_policy_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryMissionPackV1 {
    pub private: ReentryPrivateInputsV1,
    pub public_envelope: ReentryPublicEnvelopeV1,
    pub private_model_commitments: ReentryPrivateModelCommitmentsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReentryAssuranceReceiptV1 {
    pub mission_id: String,
    pub mission_pack_digest: String,
    pub backend: String,
    pub theorem_lane: String,
    pub mathematical_model: String,
    pub theorem_hypotheses: Vec<String>,
    pub horizon_steps: usize,
    pub fixed_point_scale: String,
    pub trajectory_commitment: String,
    pub terminal_state_commitment: String,
    pub peak_dynamic_pressure: String,
    pub peak_heating_rate: String,
    pub compliance_bit: bool,
    pub minimal_tcb: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryAtmosphereBandRowV1 {
    pub altitude_start: String,
    pub altitude_end: String,
    pub density_start: String,
    pub density_end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentrySineBandRowV1 {
    pub gamma_start: String,
    pub gamma_end: String,
    pub sine_start: String,
    pub sine_end: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryAbortThresholdsV1 {
    pub q_trigger_min: String,
    pub q_dot_trigger_min: String,
    pub altitude_floor: String,
    pub velocity_ceiling: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryAbortCorridorBandRowV1 {
    pub altitude_start: String,
    pub altitude_end: String,
    pub velocity_min: String,
    pub velocity_max: String,
    pub gamma_min: String,
    pub gamma_max: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryPrivateInputsV2 {
    pub initial_altitude: String,
    pub initial_velocity: String,
    pub initial_flight_path_angle: String,
    pub vehicle_mass: String,
    pub reference_area: String,
    pub drag_coefficient: String,
    pub lift_coefficient: String,
    pub nose_radius: String,
    pub bank_angle_cosines: Vec<String>,
    pub atmosphere_bands: Vec<ReentryAtmosphereBandRowV1>,
    pub sine_bands: Vec<ReentrySineBandRowV1>,
    pub abort_thresholds: ReentryAbortThresholdsV1,
    pub abort_corridor_bands: Vec<ReentryAbortCorridorBandRowV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryMissionPackV2 {
    pub private: ReentryPrivateInputsV2,
    pub public_envelope: ReentryPublicEnvelopeV1,
    pub private_model_commitments: ReentryPrivateModelCommitmentsV1,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedReentryMissionPackV1 {
    pub payload: ReentryMissionPackV2,
    pub payload_digest: String,
    pub signer_identity: String,
    pub signer_public_keys: PublicKeyBundle,
    pub signer_signature_bundle: SignatureBundle,
    pub not_before_unix_epoch_seconds: u64,
    pub not_after_unix_epoch_seconds: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryAuthorizedSignerV1 {
    pub signer_identity: String,
    pub public_keys: PublicKeyBundle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before_unix_epoch_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after_unix_epoch_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentrySignerManifestV1 {
    pub version: u32,
    pub manifest_id: String,
    pub authorized_signers: Vec<ReentryAuthorizedSignerV1>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryAssuranceReceiptV2 {
    pub mission_id: String,
    pub mission_pack_digest: String,
    pub signer_manifest_digest: String,
    pub signer_identity: String,
    pub backend: String,
    pub theorem_lane: String,
    pub model_revision: String,
    pub mathematical_model: String,
    pub theorem_hypotheses: Vec<String>,
    pub horizon_steps: usize,
    pub fixed_point_scale: String,
    pub trajectory_commitment: String,
    pub terminal_state_commitment: String,
    pub peak_dynamic_pressure: String,
    pub peak_heating_rate: String,
    pub compliance_bit: bool,
    pub minimal_tcb: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryOracleSummaryV1 {
    pub mission_id: String,
    pub mission_pack_digest: String,
    pub oracle_lane: String,
    pub model_revision: String,
    pub horizon_steps: usize,
    pub fixed_point_scale: String,
    pub peak_dynamic_pressure: String,
    pub peak_heating_rate: String,
    pub compliance_bit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReentryOracleComparisonV1 {
    pub mission_id: String,
    pub mission_pack_digest: String,
    pub theorem_lane: String,
    pub oracle_lane: String,
    pub tolerance_policy: String,
    pub compared_fields: Vec<String>,
    pub matched: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mismatches: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
struct ReentryPackSignatureEnvelopeV1<'a> {
    domain: &'static str,
    payload_digest: &'a str,
    signer_identity: &'a str,
    signer_public_keys: &'a PublicKeyBundle,
    not_before_unix_epoch_seconds: u64,
    not_after_unix_epoch_seconds: u64,
    provenance_metadata: &'a BTreeMap<String, String>,
}

impl From<ReentryPublicInputsV1> for ReentryPublicEnvelopeV1 {
    fn from(value: ReentryPublicInputsV1) -> Self {
        Self {
            q_max: value.q_max,
            q_dot_max: value.q_dot_max,
            h_min: value.h_min,
            v_max: value.v_max,
            gamma_bound: value.gamma_bound,
            g_0: value.g_0,
            k_sg: value.k_sg,
            certified_horizon_steps: value.step_count,
        }
    }
}

impl From<ReentryPublicEnvelopeV1> for ReentryPublicInputsV1 {
    fn from(value: ReentryPublicEnvelopeV1) -> Self {
        Self {
            q_max: value.q_max,
            q_dot_max: value.q_dot_max,
            h_min: value.h_min,
            v_max: value.v_max,
            gamma_bound: value.gamma_bound,
            g_0: value.g_0,
            k_sg: value.k_sg,
            step_count: value.certified_horizon_steps,
        }
    }
}

impl From<ReentryMissionPackV1> for PrivateReentryThermalRequestV1 {
    fn from(value: ReentryMissionPackV1) -> Self {
        Self {
            private: value.private,
            public: value.public_envelope.into(),
        }
    }
}

impl TryFrom<ReentryMissionPackV2> for PrivateReentryThermalRequestV1 {
    type Error = ZkfError;

    fn try_from(value: ReentryMissionPackV2) -> Result<Self, Self::Error> {
        materialize_private_reentry_request_v1_from_v2(&value)
    }
}

impl TryFrom<&ReentryMissionPackV2> for PrivateReentryThermalRequestV1 {
    type Error = ZkfError;

    fn try_from(value: &ReentryMissionPackV2) -> Result<Self, Self::Error> {
        materialize_private_reentry_request_v1_from_v2(value)
    }
}

pub fn reentry_mission_pack_v2_digest(mission_pack: &ReentryMissionPackV2) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-mission-pack-v2", mission_pack)
}

pub fn reentry_signer_manifest_digest(manifest: &ReentrySignerManifestV1) -> ZkfResult<String> {
    super::science::sha256_hex_json("reentry-signer-manifest-v1", manifest)
}

fn reentry_signed_pack_signing_message(
    payload_digest: &str,
    signer_identity: &str,
    signer_public_keys: &PublicKeyBundle,
    not_before_unix_epoch_seconds: u64,
    not_after_unix_epoch_seconds: u64,
    provenance_metadata: &BTreeMap<String, String>,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ReentryPackSignatureEnvelopeV1 {
        domain: "zkf-reentry-signed-pack-v1",
        payload_digest,
        signer_identity,
        signer_public_keys,
        not_before_unix_epoch_seconds,
        not_after_unix_epoch_seconds,
        provenance_metadata,
    })
    .map_err(|error| format!("serialize reentry pack signing message: {error}"))
}

impl SignedReentryMissionPackV1 {
    pub fn signing_message(&self) -> Result<Vec<u8>, String> {
        reentry_signed_pack_signing_message(
            &self.payload_digest,
            &self.signer_identity,
            &self.signer_public_keys,
            self.not_before_unix_epoch_seconds,
            self.not_after_unix_epoch_seconds,
            &self.provenance_metadata,
        )
    }

    pub fn verify_signatures(&self) -> bool {
        if self.signer_public_keys.scheme != SignatureScheme::HybridEd25519MlDsa87
            || self.signer_signature_bundle.scheme != SignatureScheme::HybridEd25519MlDsa87
            || !bundle_has_required_signature_material(
                &self.signer_public_keys,
                &self.signer_signature_bundle,
            )
        {
            return false;
        }
        let Ok(signing_message) = self.signing_message() else {
            return false;
        };
        verify_bundle(
            &self.signer_public_keys,
            &signing_message,
            &self.signer_signature_bundle,
            REENTRY_ASSURANCE_ML_DSA_CONTEXT,
        )
    }
}

pub fn validate_signed_reentry_mission_pack(
    signed_pack: &SignedReentryMissionPackV1,
    manifest: &ReentrySignerManifestV1,
    unix_now: u64,
) -> ZkfResult<()> {
    if signed_pack.not_before_unix_epoch_seconds > signed_pack.not_after_unix_epoch_seconds {
        return Err(ZkfError::InvalidArtifact(
            "signed reentry mission pack has an inverted validity window".to_string(),
        ));
    }
    if unix_now < signed_pack.not_before_unix_epoch_seconds
        || unix_now > signed_pack.not_after_unix_epoch_seconds
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed reentry mission pack is not valid at unix time {unix_now}"
        )));
    }

    let expected_payload_digest = reentry_mission_pack_v2_digest(&signed_pack.payload)?;
    if expected_payload_digest != signed_pack.payload_digest {
        return Err(ZkfError::InvalidArtifact(
            "signed reentry mission pack payload_digest does not match payload".to_string(),
        ));
    }
    if !signed_pack.verify_signatures() {
        return Err(ZkfError::InvalidArtifact(
            "signed reentry mission pack signature verification failed".to_string(),
        ));
    }
    if manifest.version != 1 {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported reentry signer manifest version {}",
            manifest.version
        )));
    }

    let signer = manifest
        .authorized_signers
        .iter()
        .find(|entry| entry.signer_identity == signed_pack.signer_identity)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "signed reentry mission pack signer `{}` is not authorized by the manifest",
                signed_pack.signer_identity
            ))
        })?;
    if signer.public_keys != signed_pack.signer_public_keys {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed reentry mission pack signer `{}` did not match the pinned manifest public key bundle",
            signed_pack.signer_identity
        )));
    }
    if signer.public_keys.scheme != SignatureScheme::HybridEd25519MlDsa87 {
        return Err(ZkfError::InvalidArtifact(
            "reentry signer manifest must pin hybrid Ed25519 + ML-DSA-44 signers".to_string(),
        ));
    }
    if let Some(not_before) = signer.not_before_unix_epoch_seconds
        && signed_pack.not_before_unix_epoch_seconds < not_before
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed reentry mission pack for signer `{}` starts before the manifest validity window",
            signed_pack.signer_identity
        )));
    }
    if let Some(not_after) = signer.not_after_unix_epoch_seconds
        && signed_pack.not_after_unix_epoch_seconds > not_after
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed reentry mission pack for signer `{}` extends past the manifest validity window",
            signed_pack.signer_identity
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal parameter struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReentryPublicParameters {
    q_max: BigInt,
    q_dot_max: BigInt,
    h_min: BigInt,
    v_max: BigInt,
    gamma_bound: BigInt,
    g_0: BigInt,
    k_sg: BigInt,
}

// ---------------------------------------------------------------------------
// Step computation struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ReentryStepComputation {
    // Trig identity support
    trig_identity_residual: BigInt,
    // Aerodynamics
    v_sq: BigInt,
    v_sq_fp: BigInt,
    v_sq_fp_remainder: BigInt,
    v_sq_fp_slack: BigInt,
    v_cubed_fp: BigInt,
    v_cubed_remainder: BigInt,
    v_cubed_slack: BigInt,
    rho_v_sq: BigInt,
    rho_v_sq_remainder: BigInt,
    rho_v_sq_slack: BigInt,
    q_i: BigInt, // dynamic pressure
    q_i_remainder: BigInt,
    q_i_slack: BigInt,
    drag_force: BigInt, // D = q * S_ref * C_D / SCALE
    drag_remainder: BigInt,
    drag_slack: BigInt,
    lift_cos: BigInt, // C_L * cos(sigma)
    lift_cos_remainder: BigInt,
    lift_cos_slack: BigInt,
    lift_force: BigInt, // L = q * S_ref * lift_cos / SCALE^2
    lift_remainder: BigInt,
    lift_slack: BigInt,
    // Accelerations
    drag_accel: BigInt, // D / m
    drag_accel_remainder: BigInt,
    drag_accel_slack: BigInt,
    lift_accel: BigInt, // L / m
    lift_accel_remainder: BigInt,
    lift_accel_slack: BigInt,
    g_sin_gamma: BigInt, // g * sin(gamma) / SCALE
    g_sin_gamma_remainder: BigInt,
    g_sin_gamma_slack: BigInt,
    // Velocity update: dV = (-drag_accel - g_sin_gamma) * dt / SCALE
    dv_accel: BigInt, // -drag_accel - g_sin_gamma
    dv_raw: BigInt,   // dv_accel * dt
    dv: BigInt,       // dv_raw / SCALE
    dv_remainder: BigInt,
    dv_slack: BigInt,
    // Altitude update: dh = V * sin(gamma) * dt / SCALE^2
    v_sin: BigInt,  // V * sin(gamma)
    dh_raw: BigInt, // v_sin * dt
    dh: BigInt,     // dh_raw / SCALE^2 ... actually dh_raw / SCALE
    dh_remainder: BigInt,
    dh_slack: BigInt,
    // FPA update: d_gamma_lift = lift_accel / V, d_gamma_grav = g*cos(gamma) / V
    lift_over_v: BigInt,
    lift_over_v_remainder: BigInt,
    lift_over_v_slack: BigInt,
    g_cos_gamma: BigInt,
    g_cos_gamma_remainder: BigInt,
    g_cos_gamma_slack: BigInt,
    gcos_over_v: BigInt,
    gcos_over_v_remainder: BigInt,
    gcos_over_v_slack: BigInt,
    dgamma_accel: BigInt, // lift_over_v - gcos_over_v
    dgamma_raw: BigInt,   // dgamma_accel * dt
    dgamma: BigInt,       // dgamma_raw / SCALE
    dgamma_remainder: BigInt,
    dgamma_slack: BigInt,
    // Next state
    next_altitude: BigInt,
    next_velocity: BigInt,
    next_gamma: BigInt,
    // Heating-rate support
    rho_over_rn_fp: BigInt,
    rho_over_rn_remainder: BigInt,
    rho_over_rn_slack: BigInt,
    sqrt_rho_over_rn_fp: BigInt,
    sqrt_rho_over_rn_remainder: BigInt,
    sqrt_rho_over_rn_upper_slack: BigInt,
    heating_factor: BigInt,
    heating_factor_remainder: BigInt,
    heating_factor_slack: BigInt,
    q_dot_i: BigInt,
    q_dot_remainder: BigInt,
    q_dot_slack: BigInt,
    // Safety slacks
    q_safety_slack: BigInt,     // q_max - q_i
    q_dot_safety_slack: BigInt, // q_dot_max - q_dot_i
    h_safety_slack: BigInt,     // h_i - h_min
    v_safety_slack: BigInt,     // v_max - V_i
}

// ---------------------------------------------------------------------------
// Arithmetic helpers (copied from descent.rs -- siblings cannot import)
// ---------------------------------------------------------------------------

fn zero() -> BigInt {
    BigInt::from(0u8)
}

fn one() -> BigInt {
    BigInt::from(1u8)
}

fn two() -> BigInt {
    BigInt::from(2u8)
}

fn fixed_scale() -> BigInt {
    BigInt::from(10u8).pow(REENTRY_FIXED_POINT_DECIMALS)
}

fn fixed_scale_squared() -> BigInt {
    let scale = fixed_scale();
    &scale * &scale
}

const REENTRY_ACCEPTED_FIXED_POINT_DECIMALS: u32 = 3;

fn scale_for_decimals(decimals: u32) -> BigInt {
    BigInt::from(10u8).pow(decimals)
}

fn scale_squared_for_decimals(decimals: u32) -> BigInt {
    let scale = scale_for_decimals(decimals);
    &scale * &scale
}

fn decimal_scaled_for_decimals(value: &str, decimals: u32) -> BigInt {
    fn digits_to_bigint(digits: &str) -> BigInt {
        digits
            .bytes()
            .filter(|digit| digit.is_ascii_digit())
            .fold(zero(), |acc, digit| {
                acc * BigInt::from(10u8) + BigInt::from(u32::from(digit - b'0'))
            })
    }

    let negative = value.starts_with('-');
    let body = if negative { &value[1..] } else { value };
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    let whole_value = if whole.is_empty() {
        zero()
    } else {
        digits_to_bigint(whole)
    };
    let mut fraction_digits = fraction.to_string();
    let target_digits = decimals as usize;
    if fraction_digits.len() > target_digits {
        fraction_digits.truncate(target_digits);
    }
    while fraction_digits.len() < target_digits {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * scale_for_decimals(decimals) + fraction_value;
    if negative { -scaled } else { scaled }
}

fn scaled_bigint_to_decimal_string_for_decimals(value: &BigInt, decimals: u32) -> String {
    let negative = value.sign() == Sign::Minus;
    let abs = abs_bigint(value.clone());
    let scale = scale_for_decimals(decimals);
    let whole = &abs / &scale;
    let fraction = (&abs % &scale).to_str_radix(10);
    let width = decimals as usize;
    let mut fraction = format!("{fraction:0>width$}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    let mut out = if fraction.is_empty() {
        whole.to_str_radix(10)
    } else {
        format!("{}.{}", whole.to_str_radix(10), fraction)
    };
    if negative && out != "0" {
        out.insert(0, '-');
    }
    out
}

fn accepted_scale() -> BigInt {
    scale_for_decimals(REENTRY_ACCEPTED_FIXED_POINT_DECIMALS)
}

fn accepted_scale_squared() -> BigInt {
    scale_squared_for_decimals(REENTRY_ACCEPTED_FIXED_POINT_DECIMALS)
}

fn accepted_decimal_scaled(value: &str) -> BigInt {
    decimal_scaled_for_decimals(value, REENTRY_ACCEPTED_FIXED_POINT_DECIMALS)
}

fn accepted_scaled_bigint_to_decimal_string(value: &BigInt) -> String {
    scaled_bigint_to_decimal_string_for_decimals(value, REENTRY_ACCEPTED_FIXED_POINT_DECIMALS)
}

fn field_square(value: &BigInt) -> FieldElement {
    FieldElement::from_bigint(normalize_mod(value * value, REENTRY_APP_FIELD.modulus()))
}

fn decimal_scaled(value: &str) -> BigInt {
    fn digits_to_bigint(digits: &str) -> BigInt {
        digits
            .bytes()
            .filter(|digit| digit.is_ascii_digit())
            .fold(zero(), |acc, digit| {
                acc * BigInt::from(10u8) + BigInt::from(u32::from(digit - b'0'))
            })
    }

    let negative = value.starts_with('-');
    let body = if negative { &value[1..] } else { value };
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    let whole_value = if whole.is_empty() {
        zero()
    } else {
        digits_to_bigint(whole)
    };
    let mut fraction_digits = fraction.to_string();
    let target_digits = REENTRY_FIXED_POINT_DECIMALS as usize;
    if fraction_digits.len() > target_digits {
        fraction_digits.truncate(target_digits);
    }
    while fraction_digits.len() < target_digits {
        fraction_digits.push('0');
    }
    let fraction_value = if fraction_digits.is_empty() {
        zero()
    } else {
        digits_to_bigint(&fraction_digits)
    };
    let scaled = whole_value * fixed_scale() + fraction_value;
    if negative { -scaled } else { scaled }
}

fn scaled_bigint_to_decimal_string(value: &BigInt) -> String {
    let negative = value.sign() == Sign::Minus;
    let abs = abs_bigint(value.clone());
    let scale = fixed_scale();
    let whole = &abs / &scale;
    let fraction = (&abs % &scale).to_str_radix(10);
    let width = REENTRY_FIXED_POINT_DECIMALS as usize;
    let mut fraction = format!("{fraction:0>width$}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    let mut out = if fraction.is_empty() {
        whole.to_str_radix(10)
    } else {
        format!("{}.{}", whole.to_str_radix(10), fraction)
    };
    if negative && out != "0" {
        out.insert(0, '-');
    }
    out
}

fn bits_for_bound(bound: &BigInt) -> u32 {
    if *bound <= zero() {
        1
    } else {
        bound.to_str_radix(2).len() as u32
    }
}

fn abs_bigint(value: BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        -value
    } else {
        value
    }
}

fn bigint_isqrt_floor(value: &BigInt) -> BigInt {
    if *value <= one() {
        return value.clone();
    }
    let mut low = one();
    let mut high = one() << ((bits_for_bound(value) / 2) + 2);
    while &low + &one() < high {
        let mid = (&low + &high) / BigInt::from(2u8);
        let mid_sq = &mid * &mid;
        if mid_sq <= *value {
            low = mid;
        } else {
            high = mid;
        }
    }
    low
}

fn bigint_isqrt_ceil(value: &BigInt) -> BigInt {
    let floor = bigint_isqrt_floor(value);
    if &floor * &floor == *value {
        floor
    } else {
        floor + one()
    }
}

fn field(value: BigInt) -> FieldElement {
    FieldElement::from_bigint(value)
}

fn field_ref(value: &BigInt) -> FieldElement {
    FieldElement::from_bigint(value.clone())
}

fn const_expr(value: &BigInt) -> Expr {
    Expr::Const(field_ref(value))
}

fn signal_expr(name: &str) -> Expr {
    Expr::signal(name)
}

fn mul_expr(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

fn sub_expr(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

fn add_expr(mut values: Vec<Expr>) -> Expr {
    if values.len() == 1 {
        values.remove(0)
    } else {
        Expr::Add(values)
    }
}

// ---------------------------------------------------------------------------
// Reduced-order mission-analysis bounds (fixed-point scaled)
// ---------------------------------------------------------------------------

fn altitude_bound() -> BigInt {
    decimal_scaled("200") // 200 km
}

fn velocity_bound_value() -> BigInt {
    decimal_scaled("8") // 8 km/s
}

fn gamma_bound_default() -> BigInt {
    decimal_scaled("0.5") // ~28.6 degrees
}

fn mass_bound_value() -> BigInt {
    decimal_scaled("100") // 100 tonnes
}

fn area_bound() -> BigInt {
    decimal_scaled("20") // 20 m^2 reference area
}

fn coeff_bound() -> BigInt {
    decimal_scaled("3") // aerodynamic coefficient max
}

fn nose_radius_bound() -> BigInt {
    decimal_scaled("5") // 5 m
}

fn density_bound() -> BigInt {
    decimal_scaled("2") // ~1.225 at sea level, 2 as generous bound
}

fn q_max_bound() -> BigInt {
    decimal_scaled("1000") // normalized dynamic-pressure corridor
}

fn q_dot_max_bound() -> BigInt {
    decimal_scaled("1000") // normalized heating-rate corridor
}

fn gravity_bound_value() -> BigInt {
    decimal_scaled("0.02") // 0.02 km/s^2
}

fn k_sg_bound() -> BigInt {
    decimal_scaled("0.01") // normalized Sutton-Graves proxy constant
}

fn bank_cos_bound() -> BigInt {
    fixed_scale() // |cos(sigma)| <= 1
}

fn trig_bound() -> BigInt {
    fixed_scale() // |sin|, |cos| <= 1
}

// Derived bounds
fn v_sq_bound() -> BigInt {
    let v = velocity_bound_value();
    &v * &v
}

fn v_sq_fp_bound() -> BigInt {
    &v_sq_bound() / &fixed_scale() + &one()
}

fn v_cubed_fp_bound() -> BigInt {
    (&v_sq_fp_bound() * &velocity_bound_value()) / &fixed_scale() + &one()
}

fn rho_v_sq_bound() -> BigInt {
    let rho = density_bound();
    &rho * &v_sq_bound() / &fixed_scale()
}

fn dynamic_pressure_bound() -> BigInt {
    // q = rho*V^2 / (2*SCALE), bound = density_bound*v_sq_bound / (2*SCALE)
    // but we keep it generous: rho_v_sq_bound / 2 + 1
    &rho_v_sq_bound() / &two() + &one()
}

fn drag_force_bound() -> BigInt {
    // D = q * S_ref * C_D / SCALE
    // bound = dynamic_pressure_bound * area_bound * coeff_bound / SCALE
    let num = &dynamic_pressure_bound() * &area_bound() * &coeff_bound();
    &num / &fixed_scale() + &one()
}

fn lift_cos_product_bound() -> BigInt {
    // C_L * cos(sigma), both up to their respective bounds
    let product = &coeff_bound() * &bank_cos_bound();
    &product / &fixed_scale() + &one()
}

fn lift_force_bound() -> BigInt {
    // L = q * S_ref * (C_L*cos_sigma) / SCALE^2
    // For intermediate: q * S_ref * lift_cos / SCALE
    let num = &dynamic_pressure_bound() * &area_bound() * &lift_cos_product_bound();
    &num / &fixed_scale() + &one()
}

fn acceleration_bound() -> BigInt {
    decimal_scaled("5")
}

fn velocity_delta_bound() -> BigInt {
    decimal_scaled("1")
}

fn altitude_delta_bound() -> BigInt {
    decimal_scaled("8") // V * sin(gamma) * dt, velocity in km/s
}

fn gamma_delta_bound() -> BigInt {
    decimal_scaled("0.1")
}

fn rho_over_rn_bound() -> BigInt {
    // r_n is a positive fixed-point quantity, so the worst-case quotient occurs at one LSB.
    &density_bound() * &fixed_scale() + &one()
}

fn sqrt_rho_over_rn_input_bound() -> BigInt {
    &rho_over_rn_bound() * &fixed_scale()
}

fn sqrt_rho_over_rn_bound() -> BigInt {
    bigint_isqrt_ceil(&sqrt_rho_over_rn_input_bound())
}

fn heating_factor_bound() -> BigInt {
    (&k_sg_bound() * &sqrt_rho_over_rn_bound()) / &fixed_scale() + &one()
}

fn exact_division_remainder_bound_for_scale() -> BigInt {
    fixed_scale()
}

fn exact_division_remainder_bound_for_scale_squared() -> BigInt {
    fixed_scale_squared()
}

fn sqrt_support_bound(sqrt_bound: &BigInt) -> BigInt {
    (sqrt_bound * BigInt::from(2u8)) + one()
}

fn dt_scaled() -> BigInt {
    decimal_scaled("1") // 1-second time step
}

fn trajectory_seed_tag() -> BigInt {
    BigInt::from(92_001u64)
}

fn trajectory_step_tag(step: usize) -> BigInt {
    BigInt::from(200_000u64 + step as u64)
}

fn terminal_state_tag() -> BigInt {
    BigInt::from(300_001u64)
}

fn private_input_count_for_steps(steps: usize) -> usize {
    PRIVATE_REENTRY_THERMAL_SCALAR_PRIVATE_INPUTS
        + (steps * PRIVATE_REENTRY_THERMAL_PER_STEP_INPUTS)
}

fn accepted_altitude_bound() -> BigInt {
    accepted_decimal_scaled("200")
}

fn accepted_downrange_bound() -> BigInt {
    accepted_decimal_scaled("2500")
}

fn accepted_velocity_bound() -> BigInt {
    accepted_decimal_scaled("8")
}

fn accepted_gamma_bound() -> BigInt {
    accepted_decimal_scaled("0.5")
}

fn accepted_mass_bound() -> BigInt {
    accepted_decimal_scaled("100")
}

fn accepted_area_bound() -> BigInt {
    accepted_decimal_scaled("20")
}

fn accepted_coeff_bound() -> BigInt {
    accepted_decimal_scaled("3")
}

fn accepted_nose_radius_bound() -> BigInt {
    accepted_decimal_scaled("5")
}

fn accepted_density_bound() -> BigInt {
    accepted_decimal_scaled("2")
}

fn accepted_q_max_bound() -> BigInt {
    accepted_decimal_scaled("1000")
}

fn accepted_q_dot_max_bound() -> BigInt {
    accepted_decimal_scaled("1000")
}

fn accepted_heat_bound() -> BigInt {
    accepted_q_dot_max_bound() * BigInt::from(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS as u64)
}

fn accepted_gravity_bound() -> BigInt {
    accepted_decimal_scaled("0.02")
}

fn accepted_k_sg_bound() -> BigInt {
    accepted_decimal_scaled("0.01")
}

fn accepted_trig_bound() -> BigInt {
    accepted_scale()
}

fn accepted_bank_cos_bound() -> BigInt {
    accepted_scale()
}

fn accepted_v_sq_bound() -> BigInt {
    let v = accepted_velocity_bound();
    &v * &v
}

fn accepted_v_sq_fp_bound() -> BigInt {
    &accepted_v_sq_bound() / &accepted_scale() + &one()
}

fn accepted_v_cubed_fp_bound() -> BigInt {
    (&accepted_v_sq_fp_bound() * &accepted_velocity_bound()) / &accepted_scale() + &one()
}

fn accepted_dynamic_pressure_bound() -> BigInt {
    let rho_v_sq = (&accepted_density_bound() * &accepted_v_sq_bound()) / &accepted_scale();
    &rho_v_sq / &two() + &one()
}

fn accepted_acceleration_bound() -> BigInt {
    accepted_decimal_scaled("5")
}

fn accepted_altitude_delta_bound() -> BigInt {
    accepted_decimal_scaled("8")
}

fn accepted_downrange_delta_bound() -> BigInt {
    accepted_decimal_scaled("8")
}

fn accepted_velocity_delta_bound() -> BigInt {
    accepted_decimal_scaled("1")
}

fn accepted_gamma_delta_bound() -> BigInt {
    accepted_decimal_scaled("0.1")
}

fn accepted_rho_over_rn_bound() -> BigInt {
    &accepted_density_bound() * &accepted_scale() + &one()
}

fn accepted_sqrt_rho_over_rn_input_bound() -> BigInt {
    &accepted_rho_over_rn_bound() * &accepted_scale()
}

fn accepted_sqrt_rho_over_rn_bound() -> BigInt {
    bigint_isqrt_ceil(&accepted_sqrt_rho_over_rn_input_bound())
}

fn accepted_heating_factor_bound() -> BigInt {
    (&accepted_k_sg_bound() * &accepted_sqrt_rho_over_rn_bound()) / &accepted_scale() + &one()
}

fn accepted_positive_comparison_offset(bound: &BigInt) -> BigInt {
    bound + one()
}

fn accepted_signed_comparison_offset(bound: &BigInt) -> BigInt {
    (bound * BigInt::from(2u8)) + one()
}

#[derive(Debug, Clone, Copy)]
struct AcceptedReentryShape {
    steps: usize,
    atmosphere_rows: usize,
    sine_rows: usize,
    abort_rows: usize,
}

fn accepted_shape_from_mission_pack(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<AcceptedReentryShape> {
    let steps = mission_pack.public_envelope.certified_horizon_steps;
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry lane requires a nonzero certified horizon".to_string(),
        ));
    }
    if mission_pack.private.bank_angle_cosines.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "accepted reentry lane horizon {} did not match bank-angle schedule length {}",
            steps,
            mission_pack.private.bank_angle_cosines.len()
        )));
    }
    if mission_pack.private.atmosphere_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry lane requires at least one private atmosphere band".to_string(),
        ));
    }
    if mission_pack.private.sine_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry lane requires at least one private sine band".to_string(),
        ));
    }
    if mission_pack.private.abort_corridor_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry lane requires at least one private abort corridor band".to_string(),
        ));
    }
    Ok(AcceptedReentryShape {
        steps,
        atmosphere_rows: mission_pack.private.atmosphere_bands.len(),
        sine_rows: mission_pack.private.sine_bands.len(),
        abort_rows: mission_pack.private.abort_corridor_bands.len(),
    })
}

// ---------------------------------------------------------------------------
// Signal naming functions
// ---------------------------------------------------------------------------

fn q_max_name() -> &'static str {
    "q_max"
}

fn q_dot_max_name() -> &'static str {
    "q_dot_max"
}

fn h_min_name() -> &'static str {
    "h_min"
}

fn v_max_name() -> &'static str {
    "v_max"
}

fn gamma_bound_name() -> &'static str {
    "gamma_bound"
}

fn gravity_name() -> &'static str {
    "g_0"
}

fn k_sg_name() -> &'static str {
    "k_sg"
}

fn altitude_name() -> &'static str {
    "h0"
}

fn velocity_name() -> &'static str {
    "V0"
}

fn gamma_name() -> &'static str {
    "gamma0"
}

fn mass_input_name() -> &'static str {
    "mass"
}

fn sref_name() -> &'static str {
    "S_ref"
}

fn cd_name() -> &'static str {
    "C_D"
}

fn cl_name() -> &'static str {
    "C_L"
}

fn rn_name() -> &'static str {
    "r_n"
}

fn h_state_name(step: usize) -> String {
    if step == 0 {
        altitude_name().to_string()
    } else {
        format!("step_{step}_h")
    }
}

fn v_state_name(step: usize) -> String {
    if step == 0 {
        velocity_name().to_string()
    } else {
        format!("step_{step}_V")
    }
}

fn gamma_state_name(step: usize) -> String {
    if step == 0 {
        gamma_name().to_string()
    } else {
        format!("step_{step}_gamma")
    }
}

fn bank_cos_name(step: usize) -> String {
    format!("step_{step}_bank_cos")
}

fn sin_gamma_input_name(step: usize) -> String {
    format!("step_{step}_sin_gamma")
}

fn cos_gamma_input_name(step: usize) -> String {
    format!("step_{step}_cos_gamma")
}

fn rho_name(step: usize) -> String {
    format!("step_{step}_rho")
}

fn accepted_downrange_state_name(step: usize) -> String {
    if step == 0 {
        "x0".to_string()
    } else {
        format!("step_{step}_x")
    }
}

fn accepted_heat_state_name(step: usize) -> String {
    if step == 0 {
        "heat0".to_string()
    } else {
        format!("step_{step}_heat")
    }
}

fn accepted_abort_latch_state_name(step: usize) -> String {
    format!("state_{step}_abort_latch")
}

fn accepted_stage_prefix(step: usize, stage: usize) -> String {
    format!("step_{step}_stage_{stage}")
}

fn accepted_stage_name(step: usize, stage: usize, suffix: &str) -> String {
    format!("{}_{}", accepted_stage_prefix(step, stage), suffix)
}

fn accepted_stage_altitude_name(step: usize, stage: usize) -> String {
    format!("{}_h", accepted_stage_prefix(step, stage))
}

fn accepted_stage_downrange_name(step: usize, stage: usize) -> String {
    format!("{}_x", accepted_stage_prefix(step, stage))
}

fn accepted_stage_velocity_name(step: usize, stage: usize) -> String {
    format!("{}_V", accepted_stage_prefix(step, stage))
}

fn accepted_stage_gamma_name(step: usize, stage: usize) -> String {
    format!("{}_gamma", accepted_stage_prefix(step, stage))
}

fn accepted_stage_heat_name(step: usize, stage: usize) -> String {
    format!("{}_heat", accepted_stage_prefix(step, stage))
}

fn accepted_stage_atmosphere_selector_name(step: usize, stage: usize, row: usize) -> String {
    format!(
        "{}_atmosphere_selector_{row}",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_sine_selector_name(step: usize, stage: usize, row: usize) -> String {
    format!("{}_sine_selector_{row}", accepted_stage_prefix(step, stage))
}

fn accepted_stage_abort_selector_name(step: usize, stage: usize, row: usize) -> String {
    format!(
        "{}_abort_selector_{row}",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_atmosphere_start_name(step: usize, stage: usize) -> String {
    format!(
        "{}_atmosphere_altitude_start",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_atmosphere_end_name(step: usize, stage: usize) -> String {
    format!(
        "{}_atmosphere_altitude_end",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_density_start_name(step: usize, stage: usize) -> String {
    format!(
        "{}_atmosphere_density_start",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_density_end_name(step: usize, stage: usize) -> String {
    format!(
        "{}_atmosphere_density_end",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_sine_start_name(step: usize, stage: usize) -> String {
    format!("{}_sine_gamma_start", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_sine_end_name(step: usize, stage: usize) -> String {
    format!("{}_sine_gamma_end", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_sine_value_start_name(step: usize, stage: usize) -> String {
    format!("{}_sine_value_start", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_sine_value_end_name(step: usize, stage: usize) -> String {
    format!("{}_sine_value_end", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_abort_altitude_start_name(step: usize, stage: usize) -> String {
    format!(
        "{}_abort_altitude_start",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_selected_abort_altitude_end_name(step: usize, stage: usize) -> String {
    format!("{}_abort_altitude_end", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_abort_velocity_min_name(step: usize, stage: usize) -> String {
    format!("{}_abort_velocity_min", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_abort_velocity_max_name(step: usize, stage: usize) -> String {
    format!("{}_abort_velocity_max", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_abort_gamma_min_name(step: usize, stage: usize) -> String {
    format!("{}_abort_gamma_min", accepted_stage_prefix(step, stage))
}

fn accepted_stage_selected_abort_gamma_max_name(step: usize, stage: usize) -> String {
    format!("{}_abort_gamma_max", accepted_stage_prefix(step, stage))
}

fn accepted_stage_rho_name(step: usize, stage: usize) -> String {
    format!("{}_rho", accepted_stage_prefix(step, stage))
}

fn accepted_stage_sin_gamma_name(step: usize, stage: usize) -> String {
    format!("{}_sin_gamma", accepted_stage_prefix(step, stage))
}

fn accepted_stage_cos_gamma_name(step: usize, stage: usize) -> String {
    format!("{}_cos_gamma", accepted_stage_prefix(step, stage))
}

fn accepted_stage_cos_remainder_name(step: usize, stage: usize) -> String {
    format!("{}_cos_remainder", accepted_stage_prefix(step, stage))
}

fn accepted_stage_cos_upper_slack_name(step: usize, stage: usize) -> String {
    format!("{}_cos_upper_slack", accepted_stage_prefix(step, stage))
}

fn accepted_stage_q_name(step: usize, stage: usize) -> String {
    format!("{}_q", accepted_stage_prefix(step, stage))
}

fn accepted_stage_q_dot_name(step: usize, stage: usize) -> String {
    format!("{}_q_dot", accepted_stage_prefix(step, stage))
}

fn accepted_stage_q_ok_name(step: usize, stage: usize) -> String {
    format!("{}_q_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_q_dot_ok_name(step: usize, stage: usize) -> String {
    format!("{}_q_dot_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_altitude_ok_name(step: usize, stage: usize) -> String {
    format!("{}_altitude_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_velocity_ok_name(step: usize, stage: usize) -> String {
    format!("{}_velocity_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_gamma_lower_ok_name(step: usize, stage: usize) -> String {
    format!("{}_gamma_lower_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_gamma_upper_ok_name(step: usize, stage: usize) -> String {
    format!("{}_gamma_upper_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_gamma_ok_name(step: usize, stage: usize) -> String {
    format!("{}_gamma_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_nominal_ok_name(step: usize, stage: usize) -> String {
    format!("{}_nominal_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_dx_name(step: usize, stage: usize) -> String {
    format!("{}_dx", accepted_stage_prefix(step, stage))
}

fn accepted_stage_dh_name(step: usize, stage: usize) -> String {
    format!("{}_dh", accepted_stage_prefix(step, stage))
}

fn accepted_stage_dv_name(step: usize, stage: usize) -> String {
    format!("{}_dv", accepted_stage_prefix(step, stage))
}

fn accepted_stage_dgamma_name(step: usize, stage: usize) -> String {
    format!("{}_dgamma", accepted_stage_prefix(step, stage))
}

fn accepted_stage_abort_velocity_ok_name(step: usize, stage: usize) -> String {
    format!("{}_abort_velocity_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_abort_gamma_lower_ok_name(step: usize, stage: usize) -> String {
    format!(
        "{}_abort_gamma_lower_ok",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_abort_gamma_upper_ok_name(step: usize, stage: usize) -> String {
    format!(
        "{}_abort_gamma_upper_ok",
        accepted_stage_prefix(step, stage)
    )
}

fn accepted_stage_abort_gamma_ok_name(step: usize, stage: usize) -> String {
    format!("{}_abort_gamma_ok", accepted_stage_prefix(step, stage))
}

fn accepted_stage_abort_ok_name(step: usize, stage: usize) -> String {
    format!("{}_abort_ok", accepted_stage_prefix(step, stage))
}

fn accepted_weighted_delta_name(step: usize, label: &str) -> String {
    format!("step_{step}_rk4_{label}")
}

fn accepted_q_abort_predicate_name(step: usize) -> String {
    format!("step_{step}_abort_q_predicate")
}

fn accepted_q_dot_abort_predicate_name(step: usize) -> String {
    format!("step_{step}_abort_q_dot_predicate")
}

fn accepted_altitude_abort_predicate_name(step: usize) -> String {
    format!("step_{step}_abort_altitude_predicate")
}

fn accepted_velocity_abort_predicate_name(step: usize) -> String {
    format!("step_{step}_abort_velocity_predicate")
}

fn accepted_trigger_name(step: usize) -> String {
    format!("step_{step}_abort_trigger")
}

fn accepted_first_trigger_name(step: usize) -> String {
    format!("step_{step}_first_abort_trigger")
}

fn accepted_nominal_ok_name(step: usize) -> String {
    format!("step_{step}_nominal_ok")
}

fn accepted_abort_ok_name(step: usize) -> String {
    format!("step_{step}_abort_ok")
}

fn accepted_step_valid_name(step: usize) -> String {
    format!("step_{step}_valid")
}

fn accepted_atmosphere_altitude_start_name(row: usize) -> String {
    format!("atmosphere_row_{row}_altitude_start")
}

fn accepted_atmosphere_altitude_end_name(row: usize) -> String {
    format!("atmosphere_row_{row}_altitude_end")
}

fn accepted_atmosphere_density_start_name(row: usize) -> String {
    format!("atmosphere_row_{row}_density_start")
}

fn accepted_atmosphere_density_end_name(row: usize) -> String {
    format!("atmosphere_row_{row}_density_end")
}

fn accepted_sine_gamma_start_name(row: usize) -> String {
    format!("sine_row_{row}_gamma_start")
}

fn accepted_sine_gamma_end_name(row: usize) -> String {
    format!("sine_row_{row}_gamma_end")
}

fn accepted_sine_value_start_name(row: usize) -> String {
    format!("sine_row_{row}_sine_start")
}

fn accepted_sine_value_end_name(row: usize) -> String {
    format!("sine_row_{row}_sine_end")
}

fn accepted_abort_altitude_start_name(row: usize) -> String {
    format!("abort_row_{row}_altitude_start")
}

fn accepted_abort_altitude_end_name(row: usize) -> String {
    format!("abort_row_{row}_altitude_end")
}

fn accepted_abort_velocity_min_name(row: usize) -> String {
    format!("abort_row_{row}_velocity_min")
}

fn accepted_abort_velocity_max_name(row: usize) -> String {
    format!("abort_row_{row}_velocity_max")
}

fn accepted_abort_gamma_min_name(row: usize) -> String {
    format!("abort_row_{row}_gamma_min")
}

fn accepted_abort_gamma_max_name(row: usize) -> String {
    format!("abort_row_{row}_gamma_max")
}

fn accepted_abort_q_trigger_name() -> &'static str {
    "abort_q_trigger_min"
}

fn accepted_abort_q_dot_trigger_name() -> &'static str {
    "abort_q_dot_trigger_min"
}

fn accepted_abort_altitude_floor_name() -> &'static str {
    "abort_altitude_floor"
}

fn accepted_abort_velocity_ceiling_name() -> &'static str {
    "abort_velocity_ceiling"
}

fn accepted_atmosphere_row_input_names(row: usize) -> Vec<String> {
    vec![
        accepted_atmosphere_altitude_start_name(row),
        accepted_atmosphere_altitude_end_name(row),
        accepted_atmosphere_density_start_name(row),
        accepted_atmosphere_density_end_name(row),
    ]
}

fn accepted_sine_row_input_names(row: usize) -> Vec<String> {
    vec![
        accepted_sine_gamma_start_name(row),
        accepted_sine_gamma_end_name(row),
        accepted_sine_value_start_name(row),
        accepted_sine_value_end_name(row),
    ]
}

fn accepted_abort_row_input_names(row: usize) -> Vec<String> {
    vec![
        accepted_abort_altitude_start_name(row),
        accepted_abort_altitude_end_name(row),
        accepted_abort_velocity_min_name(row),
        accepted_abort_velocity_max_name(row),
        accepted_abort_gamma_min_name(row),
        accepted_abort_gamma_max_name(row),
    ]
}

fn trig_residual_name(step: usize) -> String {
    format!("step_{step}_trig_residual")
}

fn v_sq_signal_name(step: usize) -> String {
    format!("step_{step}_v_sq")
}

fn v_sq_fp_signal_name(step: usize) -> String {
    format!("step_{step}_v_sq_fp")
}

fn v_sq_fp_remainder_name(step: usize) -> String {
    format!("step_{step}_v_sq_fp_remainder")
}

fn v_sq_fp_slack_name(step: usize) -> String {
    format!("step_{step}_v_sq_fp_remainder_slack")
}

fn v_cubed_fp_signal_name(step: usize) -> String {
    format!("step_{step}_v_cubed_fp")
}

fn v_cubed_remainder_name(step: usize) -> String {
    format!("step_{step}_v_cubed_remainder")
}

fn v_cubed_slack_name(step: usize) -> String {
    format!("step_{step}_v_cubed_remainder_slack")
}

fn rho_v_sq_signal_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq")
}

fn rho_v_sq_remainder_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq_remainder")
}

fn rho_v_sq_slack_name(step: usize) -> String {
    format!("step_{step}_rho_v_sq_remainder_slack")
}

fn q_signal_name(step: usize) -> String {
    format!("step_{step}_q")
}

fn q_remainder_name(step: usize) -> String {
    format!("step_{step}_q_remainder")
}

fn q_slack_signal_name(step: usize) -> String {
    format!("step_{step}_q_remainder_slack")
}

fn drag_signal_name(step: usize) -> String {
    format!("step_{step}_drag")
}

fn drag_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_drag_remainder")
}

fn drag_slack_signal_name(step: usize) -> String {
    format!("step_{step}_drag_remainder_slack")
}

fn lift_cos_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos")
}

fn lift_cos_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos_remainder")
}

fn lift_cos_slack_signal_name(step: usize) -> String {
    format!("step_{step}_lift_cos_remainder_slack")
}

fn lift_signal_name(step: usize) -> String {
    format!("step_{step}_lift")
}

fn lift_remainder_signal_name(step: usize) -> String {
    format!("step_{step}_lift_remainder")
}

fn lift_slack_signal_name(step: usize) -> String {
    format!("step_{step}_lift_remainder_slack")
}

fn drag_accel_signal_name(step: usize) -> String {
    format!("step_{step}_drag_accel")
}

fn drag_accel_remainder_name(step: usize) -> String {
    format!("step_{step}_drag_accel_remainder")
}

fn drag_accel_slack_name(step: usize) -> String {
    format!("step_{step}_drag_accel_remainder_slack")
}

fn lift_accel_signal_name(step: usize) -> String {
    format!("step_{step}_lift_accel")
}

fn lift_accel_remainder_name(step: usize) -> String {
    format!("step_{step}_lift_accel_remainder")
}

fn lift_accel_slack_name(step: usize) -> String {
    format!("step_{step}_lift_accel_remainder_slack")
}

fn g_sin_gamma_signal_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma")
}

fn g_sin_gamma_remainder_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma_remainder")
}

fn g_sin_gamma_slack_name(step: usize) -> String {
    format!("step_{step}_g_sin_gamma_remainder_slack")
}

fn dv_accel_signal_name(step: usize) -> String {
    format!("step_{step}_dv_accel")
}

fn dv_signal_name(step: usize) -> String {
    format!("step_{step}_dv")
}

fn dv_remainder_name(step: usize) -> String {
    format!("step_{step}_dv_remainder")
}

fn dv_slack_name(step: usize) -> String {
    format!("step_{step}_dv_remainder_slack")
}

fn v_sin_signal_name(step: usize) -> String {
    format!("step_{step}_v_sin")
}

fn dh_signal_name(step: usize) -> String {
    format!("step_{step}_dh")
}

fn dh_remainder_name(step: usize) -> String {
    format!("step_{step}_dh_remainder")
}

fn dh_slack_name(step: usize) -> String {
    format!("step_{step}_dh_remainder_slack")
}

fn lift_over_v_signal_name(step: usize) -> String {
    format!("step_{step}_lift_over_v")
}

fn lift_over_v_remainder_name(step: usize) -> String {
    format!("step_{step}_lift_over_v_remainder")
}

fn lift_over_v_slack_name(step: usize) -> String {
    format!("step_{step}_lift_over_v_remainder_slack")
}

fn g_cos_gamma_signal_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma")
}

fn g_cos_gamma_remainder_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma_remainder")
}

fn g_cos_gamma_slack_name(step: usize) -> String {
    format!("step_{step}_g_cos_gamma_remainder_slack")
}

fn gcos_over_v_signal_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v")
}

fn gcos_over_v_remainder_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v_remainder")
}

fn gcos_over_v_slack_name(step: usize) -> String {
    format!("step_{step}_gcos_over_v_remainder_slack")
}

fn dgamma_accel_signal_name(step: usize) -> String {
    format!("step_{step}_dgamma_accel")
}

fn dgamma_signal_name(step: usize) -> String {
    format!("step_{step}_dgamma")
}

fn dgamma_remainder_name(step: usize) -> String {
    format!("step_{step}_dgamma_remainder")
}

fn dgamma_slack_name(step: usize) -> String {
    format!("step_{step}_dgamma_remainder_slack")
}

fn q_dot_signal_name(step: usize) -> String {
    format!("step_{step}_q_dot")
}

fn q_dot_remainder_name(step: usize) -> String {
    format!("step_{step}_q_dot_remainder")
}

fn q_dot_slack_name(step: usize) -> String {
    format!("step_{step}_q_dot_remainder_slack")
}

fn rho_over_rn_signal_name(step: usize) -> String {
    format!("step_{step}_rho_over_rn")
}

fn rho_over_rn_remainder_name(step: usize) -> String {
    format!("step_{step}_rho_over_rn_remainder")
}

fn rho_over_rn_slack_name(step: usize) -> String {
    format!("step_{step}_rho_over_rn_remainder_slack")
}

fn sqrt_rho_over_rn_signal_name(step: usize) -> String {
    format!("step_{step}_sqrt_rho_over_rn")
}

fn sqrt_rho_over_rn_remainder_name(step: usize) -> String {
    format!("step_{step}_sqrt_rho_over_rn_remainder")
}

fn sqrt_rho_over_rn_upper_slack_name(step: usize) -> String {
    format!("step_{step}_sqrt_rho_over_rn_upper_slack")
}

fn heating_factor_signal_name(step: usize) -> String {
    format!("step_{step}_heating_factor")
}

fn heating_factor_remainder_name(step: usize) -> String {
    format!("step_{step}_heating_factor_remainder")
}

fn heating_factor_slack_name(step: usize) -> String {
    format!("step_{step}_heating_factor_remainder_slack")
}

fn q_safety_slack_name(step: usize) -> String {
    format!("step_{step}_q_safety_slack")
}

fn nonlinear_anchor_name(signal: &str) -> String {
    format!("{signal}_anchor")
}

fn q_dot_safety_slack_name(step: usize) -> String {
    format!("step_{step}_q_dot_safety_slack")
}

fn h_safety_slack_signal_name(step: usize) -> String {
    format!("step_{step}_h_safety_slack")
}

fn v_safety_slack_signal_name(step: usize) -> String {
    format!("step_{step}_v_safety_slack")
}

fn trajectory_commitment_output_name() -> &'static str {
    "trajectory_commitment"
}

fn terminal_state_commitment_output_name() -> &'static str {
    "terminal_state_commitment"
}

fn constraint_satisfaction_output_name() -> &'static str {
    "constraint_satisfaction"
}

fn peak_q_output_name() -> &'static str {
    "peak_dynamic_pressure"
}

fn peak_q_dot_output_name() -> &'static str {
    "peak_heating_rate"
}

fn running_max_q_name(step: usize) -> String {
    format!("state_{step}_running_max_q")
}

fn running_max_q_prev_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_prev_slack")
}

fn running_max_q_curr_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_curr_slack")
}

fn running_max_q_dot_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot")
}

fn running_max_q_dot_prev_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot_prev_slack")
}

fn running_max_q_dot_curr_slack_name(step: usize) -> String {
    format!("state_{step}_running_max_q_dot_curr_slack")
}

fn signed_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_signed_bound_slack")
}

fn nonnegative_bound_slack_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_slack")
}

fn nonnegative_bound_anchor_name(prefix: &str) -> String {
    format!("{prefix}_nonnegative_bound_anchor")
}

fn nonzero_inverse_name(prefix: &str) -> String {
    format!("{prefix}_nonzero_inverse")
}

fn exact_division_slack_anchor_name(prefix: &str) -> String {
    format!("{prefix}_slack_anchor")
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_state_0"),
        format!("{prefix}_state_1"),
        format!("{prefix}_state_2"),
        format!("{prefix}_state_3"),
    ]
}

// ---------------------------------------------------------------------------
// Value / input helpers (copied from descent.rs)
// ---------------------------------------------------------------------------

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: BigInt,
) {
    values.insert(name.into(), field(value));
}

fn write_bool_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: bool,
) {
    write_value(values, name, if value { one() } else { zero() });
}

fn read_input(inputs: &WitnessInputs, name: &str) -> ZkfResult<BigInt> {
    inputs
        .get(name)
        .map(FieldElement::as_bigint)
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: name.to_string(),
        })
}

fn ensure_abs_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if abs_bigint(value.clone()) > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} exceeded signed bound {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn ensure_nonnegative_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value < zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} must satisfy 0 <= value <= {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn ensure_positive_le(name: &str, value: &BigInt, bound: &BigInt) -> ZkfResult<()> {
    if *value <= zero() || *value > *bound {
        return Err(ZkfError::InvalidArtifact(format!(
            "{name} must satisfy 0 < value <= {}",
            bound.to_str_radix(10)
        )));
    }
    Ok(())
}

fn write_signed_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = (bound * bound) - (value * value);
    if slack < zero() {
        return Err(ZkfError::InvalidArtifact(format!(
            "signed bound slack underflow for {prefix}"
        )));
    }
    write_value(values, signed_bound_slack_name(prefix), slack);
    Ok(())
}

fn write_nonnegative_bound_support(
    values: &mut BTreeMap<String, FieldElement>,
    signal_name: impl Into<String>,
    value: &BigInt,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    ensure_nonnegative_le(prefix, value, bound)?;
    let signal_name = signal_name.into();
    values.insert(signal_name, field_ref(value));
    let slack = bound - value;
    let slack_field = field_ref(&slack);
    values.insert(nonnegative_bound_slack_name(prefix), slack_field.clone());
    values.insert(nonnegative_bound_anchor_name(prefix), field_square(&slack));
    Ok(())
}

fn write_nonzero_inverse_support(
    values: &mut BTreeMap<String, FieldElement>,
    value: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let inverse =
        mod_inverse_bigint(value.clone(), REENTRY_APP_FIELD.modulus()).ok_or_else(|| {
            ZkfError::InvalidArtifact(format!("failed to compute field inverse for {prefix}"))
        })?;
    write_value(values, nonzero_inverse_name(prefix), inverse);
    Ok(())
}

fn write_exact_division_slack_anchor(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    slack: &BigInt,
) {
    values.insert(
        exact_division_slack_anchor_name(prefix),
        field_square(slack),
    );
}

// ---------------------------------------------------------------------------
// Constraint-builder helpers (copied from descent.rs)
// ---------------------------------------------------------------------------

fn append_signed_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = signed_bound_slack_name(prefix);
    let bound_squared = bound * bound;
    builder.private_signal(&slack)?;
    builder.constrain_equal(
        add_expr(vec![
            mul_expr(signal_expr(signal), signal_expr(signal)),
            signal_expr(&slack),
        ]),
        const_expr(&bound_squared),
    )?;
    builder.constrain_range(&slack, bits_for_bound(&bound_squared))?;
    Ok(())
}

fn append_nonnegative_bound(
    builder: &mut ProgramBuilder,
    signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack = nonnegative_bound_slack_name(prefix);
    let anchor = nonnegative_bound_anchor_name(prefix);
    builder.private_signal(&slack)?;
    builder.private_signal(&anchor)?;
    builder.constrain_range(signal, bits_for_bound(bound))?;
    builder.constrain_equal(
        add_expr(vec![signal_expr(signal), signal_expr(&slack)]),
        const_expr(bound),
    )?;
    builder.constrain_range(&slack, bits_for_bound(bound))?;
    builder.constrain_equal(
        signal_expr(&anchor),
        mul_expr(signal_expr(&slack), signal_expr(&slack)),
    )?;
    Ok(())
}

fn append_nonzero_constraint(
    builder: &mut ProgramBuilder,
    signal: &str,
    prefix: &str,
) -> ZkfResult<()> {
    let inverse = nonzero_inverse_name(prefix);
    builder.private_signal(&inverse)?;
    builder.constrain_equal(
        mul_expr(signal_expr(signal), signal_expr(&inverse)),
        Expr::Const(FieldElement::ONE),
    )?;
    Ok(())
}

fn append_geq_comparator_bit(
    builder: &mut ProgramBuilder,
    lhs: Expr,
    rhs: Expr,
    bit_signal: &str,
    slack_signal: &str,
    offset: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    builder.private_signal(bit_signal)?;
    builder.constrain_boolean(bit_signal)?;
    builder.private_signal(slack_signal)?;
    builder.constrain_equal(
        add_expr(vec![lhs, const_expr(offset)]),
        add_expr(vec![
            rhs,
            signal_expr(slack_signal),
            mul_expr(signal_expr(bit_signal), const_expr(offset)),
        ]),
    )?;
    append_nonnegative_bound(
        builder,
        slack_signal,
        &(offset - one()),
        &format!("{prefix}_comparator_slack"),
    )?;
    Ok(())
}

fn comparator_slack(lhs: &BigInt, rhs: &BigInt, offset: &BigInt) -> BigInt {
    if lhs >= rhs {
        lhs - rhs
    } else {
        lhs - rhs + offset
    }
}

fn geq_bit(lhs: &BigInt, rhs: &BigInt) -> bool {
    lhs >= rhs
}

fn bool_not(value: bool) -> bool {
    !value
}

fn bool_and(left: bool, right: bool) -> bool {
    left && right
}

fn bool_or(left: bool, right: bool) -> bool {
    left || right
}

fn append_boolean_not(builder: &mut ProgramBuilder, target: &str, source: &str) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        sub_expr(const_expr(&one()), signal_expr(source)),
    )?;
    Ok(())
}

fn append_boolean_and(
    builder: &mut ProgramBuilder,
    target: &str,
    left: &str,
    right: &str,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        mul_expr(signal_expr(left), signal_expr(right)),
    )?;
    Ok(())
}

fn append_boolean_or(
    builder: &mut ProgramBuilder,
    target: &str,
    left: &str,
    right: &str,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.constrain_boolean(target)?;
    builder.constrain_equal(
        signal_expr(target),
        sub_expr(
            add_expr(vec![signal_expr(left), signal_expr(right)]),
            mul_expr(signal_expr(left), signal_expr(right)),
        ),
    )?;
    Ok(())
}

fn append_pairwise_max_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let bit_signal = format!("{prefix}_geq_bit");
    let slack_signal = format!("{prefix}_geq_slack");
    append_geq_comparator_bit(
        builder,
        signal_expr(left_signal),
        signal_expr(right_signal),
        &bit_signal,
        &slack_signal,
        &accepted_positive_comparison_offset(bound),
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.constrain_select(
        target,
        &bit_signal,
        signal_expr(left_signal),
        signal_expr(right_signal),
    )?;
    append_nonnegative_bound(builder, target, bound, &format!("{prefix}_bound"))?;
    Ok(())
}

fn append_one_hot_row_selection(
    builder: &mut ProgramBuilder,
    prefix: &str,
    row_inputs: &[Vec<String>],
    selected_fields: &[String],
    selector_names: &[String],
) -> ZkfResult<()> {
    for selector in selector_names {
        builder.private_signal(selector)?;
        builder.constrain_boolean(selector)?;
    }
    builder.constrain_exactly_one(selector_names)?;
    for (field_index, selected_field) in selected_fields.iter().enumerate() {
        builder.private_signal(selected_field)?;
        let mux_values = row_inputs
            .iter()
            .map(|row| signal_expr(&row[field_index]))
            .collect::<Vec<_>>();
        builder.constrain_mux_from_one_hot(selected_field, selector_names, &mux_values)?;
    }
    builder.metadata_entry(
        format!("{prefix}_selection_surface"),
        format!("one_hot:{}_rows", row_inputs.len()),
    )?;
    Ok(())
}

fn append_piecewise_interpolation_constraints(
    builder: &mut ProgramBuilder,
    prefix: &str,
    input_signal: &str,
    selected_input_start: &str,
    selected_input_end: &str,
    selected_value_start: &str,
    selected_value_end: &str,
    interpolated_signal: &str,
    input_bound: &BigInt,
    output_bound: &BigInt,
    output_signed: bool,
) -> ZkfResult<()> {
    let span_signal = format!("{prefix}_span");
    let offset_signal = format!("{prefix}_offset");
    let upper_slack_signal = format!("{prefix}_upper_slack");
    let delta_signal = format!("{prefix}_delta");
    let quotient_signal = format!("{prefix}_quotient");
    let remainder_signal = format!("{prefix}_remainder");
    let slack_signal = format!("{prefix}_remainder_slack");

    builder.private_signal(&span_signal)?;
    builder.constrain_equal(
        signal_expr(&span_signal),
        sub_expr(
            signal_expr(selected_input_end),
            signal_expr(selected_input_start),
        ),
    )?;
    append_nonnegative_bound(
        builder,
        &span_signal,
        input_bound,
        &format!("{prefix}_span"),
    )?;
    append_nonzero_constraint(builder, &span_signal, &format!("{prefix}_span"))?;

    builder.private_signal(&offset_signal)?;
    builder.constrain_equal(
        signal_expr(&offset_signal),
        sub_expr(signal_expr(input_signal), signal_expr(selected_input_start)),
    )?;
    append_nonnegative_bound(
        builder,
        &offset_signal,
        input_bound,
        &format!("{prefix}_offset"),
    )?;

    builder.private_signal(&upper_slack_signal)?;
    builder.constrain_equal(
        signal_expr(&upper_slack_signal),
        sub_expr(signal_expr(selected_input_end), signal_expr(input_signal)),
    )?;
    append_nonnegative_bound(
        builder,
        &upper_slack_signal,
        input_bound,
        &format!("{prefix}_upper"),
    )?;

    builder.private_signal(&delta_signal)?;
    builder.constrain_equal(
        signal_expr(&delta_signal),
        sub_expr(
            signal_expr(selected_value_end),
            signal_expr(selected_value_start),
        ),
    )?;
    if output_signed {
        append_signed_bound(
            builder,
            &delta_signal,
            &(output_bound * BigInt::from(2u8)),
            &format!("{prefix}_delta"),
        )?;
    } else {
        append_nonnegative_bound(
            builder,
            &delta_signal,
            output_bound,
            &format!("{prefix}_delta"),
        )?;
    }

    append_exact_division_constraints(
        builder,
        mul_expr(signal_expr(&offset_signal), signal_expr(&delta_signal)),
        signal_expr(&span_signal),
        &quotient_signal,
        &remainder_signal,
        &slack_signal,
        input_bound,
        prefix,
    )?;
    builder.private_signal(interpolated_signal)?;
    builder.constrain_equal(
        signal_expr(interpolated_signal),
        add_expr(vec![
            signal_expr(selected_value_start),
            signal_expr(&quotient_signal),
        ]),
    )?;
    if output_signed {
        append_signed_bound(
            builder,
            interpolated_signal,
            output_bound,
            &format!("{prefix}_value"),
        )?;
    } else {
        append_nonnegative_bound(
            builder,
            interpolated_signal,
            output_bound,
            &format!("{prefix}_value"),
        )?;
    }
    Ok(())
}

fn append_poseidon_hash(
    builder: &mut ProgramBuilder,
    prefix: &str,
    inputs: [Expr; 4],
) -> ZkfResult<String> {
    let states = hash_state_names(prefix);
    for lane in &states {
        builder.private_signal(lane)?;
    }
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    builder.constrain_blackbox(
        BlackBoxOp::Poseidon,
        &inputs,
        &[
            states[0].as_str(),
            states[1].as_str(),
            states[2].as_str(),
            states[3].as_str(),
        ],
        &params,
    )?;
    Ok(states[0].clone())
}

#[allow(clippy::too_many_arguments)]
fn append_exact_division_constraints(
    builder: &mut ProgramBuilder,
    numerator: Expr,
    denominator: Expr,
    quotient: &str,
    remainder: &str,
    slack: &str,
    remainder_bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    let slack_anchor = exact_division_slack_anchor_name(prefix);
    builder.private_signal(quotient)?;
    builder.private_signal(remainder)?;
    builder.private_signal(slack)?;
    builder.private_signal(&slack_anchor)?;
    builder.constrain_equal(
        numerator,
        add_expr(vec![
            mul_expr(denominator.clone(), signal_expr(quotient)),
            signal_expr(remainder),
        ]),
    )?;
    builder.constrain_equal(
        denominator,
        add_expr(vec![
            signal_expr(remainder),
            signal_expr(slack),
            const_expr(&one()),
        ]),
    )?;
    builder.constrain_range(remainder, bits_for_bound(remainder_bound))?;
    builder.constrain_range(slack, bits_for_bound(remainder_bound))?;
    builder.constrain_equal(
        signal_expr(&slack_anchor),
        mul_expr(signal_expr(slack), signal_expr(slack)),
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_floor_sqrt_constraints(
    builder: &mut ProgramBuilder,
    value: Expr,
    sqrt_signal: &str,
    remainder_signal: &str,
    upper_slack_signal: &str,
    sqrt_bound: &BigInt,
    support_bound: &BigInt,
    prefix: &str,
) -> ZkfResult<()> {
    builder.private_signal(sqrt_signal)?;
    builder.private_signal(remainder_signal)?;
    builder.private_signal(upper_slack_signal)?;
    append_nonnegative_bound(
        builder,
        sqrt_signal,
        sqrt_bound,
        &format!("{prefix}_sqrt_bound"),
    )?;
    builder.constrain_equal(
        value.clone(),
        add_expr(vec![
            mul_expr(signal_expr(sqrt_signal), signal_expr(sqrt_signal)),
            signal_expr(remainder_signal),
        ]),
    )?;
    builder.constrain_equal(
        add_expr(vec![
            value,
            signal_expr(upper_slack_signal),
            const_expr(&one()),
        ]),
        mul_expr(
            add_expr(vec![signal_expr(sqrt_signal), const_expr(&one())]),
            add_expr(vec![signal_expr(sqrt_signal), const_expr(&one())]),
        ),
    )?;
    builder.constrain_range(remainder_signal, bits_for_bound(support_bound))?;
    builder.constrain_range(upper_slack_signal, bits_for_bound(support_bound))?;
    Ok(())
}

fn write_hash_lanes(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    lanes: [FieldElement; 4],
) -> FieldElement {
    for (lane_name, lane) in hash_state_names(prefix)
        .into_iter()
        .zip(lanes.iter().cloned())
    {
        values.insert(lane_name, lane);
    }
    lanes[0].clone()
}

fn poseidon_permutation4_reentry(inputs: [&BigInt; 4]) -> ZkfResult<[FieldElement; 4]> {
    let values = inputs.into_iter().cloned().collect::<Vec<_>>();
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    let lanes = poseidon2_permutation_native(&values, &params, REENTRY_APP_FIELD)
        .map_err(ZkfError::Backend)?;
    if lanes.len() != 4 {
        return Err(ZkfError::Backend(format!(
            "reentry poseidon permutation returned {} lanes instead of 4",
            lanes.len()
        )));
    }
    let lanes = lanes
        .into_iter()
        .map(FieldElement::from_bigint)
        .collect::<Vec<_>>();
    Ok([
        lanes[0].clone(),
        lanes[1].clone(),
        lanes[2].clone(),
        lanes[3].clone(),
    ])
}

// ---------------------------------------------------------------------------
// Euclidean division and floor-sqrt support (copied from descent.rs)
// ---------------------------------------------------------------------------

fn euclidean_division(
    numerator: &BigInt,
    denominator: &BigInt,
) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *denominator <= zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division denominator must be positive".to_string(),
        ));
    }
    let mut quotient = numerator / denominator;
    let mut remainder = numerator % denominator;
    if remainder.sign() == Sign::Minus {
        quotient -= one();
        remainder += denominator;
    }
    let slack = denominator - &remainder - one();
    if remainder < zero() || slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "exact division support underflow".to_string(),
        ));
    }
    Ok((quotient, remainder, slack))
}

fn floor_sqrt_support(value: &BigInt) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    if *value < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support expects a nonnegative value".to_string(),
        ));
    }
    let sqrt = bigint_isqrt_floor(value);
    let remainder = value - (&sqrt * &sqrt);
    let next = &sqrt + one();
    let upper_slack = (&next * &next) - value - one();
    if remainder < zero() || upper_slack < zero() {
        return Err(ZkfError::InvalidArtifact(
            "sqrt support underflow".to_string(),
        ));
    }
    Ok((sqrt, remainder, upper_slack))
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

fn parse_decimal_string(name: &str, value: &str) -> ZkfResult<BigInt> {
    if value.trim().is_empty() {
        return Err(ZkfError::Serialization(format!("{name} must not be empty")));
    }
    Ok(decimal_scaled(value))
}

fn insert_request_inputs(
    inputs: &mut WitnessInputs,
    request: &PrivateReentryThermalRequestV1,
) -> ZkfResult<()> {
    let steps = request.public.step_count;
    if steps == 0 {
        return Err(ZkfError::Serialization(
            "reentry thermal request step_count must be greater than zero".to_string(),
        ));
    }
    if request.private.bank_angle_cosines.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match bank_angle_cosines length={}",
            steps,
            request.private.bank_angle_cosines.len()
        )));
    }
    if request.private.sin_gamma.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match sin_gamma length={}",
            steps,
            request.private.sin_gamma.len()
        )));
    }
    if request.private.cos_gamma.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match cos_gamma length={}",
            steps,
            request.private.cos_gamma.len()
        )));
    }
    if request.private.density_profile.len() != steps {
        return Err(ZkfError::Serialization(format!(
            "reentry thermal request step_count={} does not match density_profile length={}",
            steps,
            request.private.density_profile.len()
        )));
    }

    // Public inputs
    inputs.insert(
        q_max_name().to_string(),
        field(parse_decimal_string(q_max_name(), &request.public.q_max)?),
    );
    inputs.insert(
        q_dot_max_name().to_string(),
        field(parse_decimal_string(
            q_dot_max_name(),
            &request.public.q_dot_max,
        )?),
    );
    inputs.insert(
        h_min_name().to_string(),
        field(parse_decimal_string(h_min_name(), &request.public.h_min)?),
    );
    inputs.insert(
        v_max_name().to_string(),
        field(parse_decimal_string(v_max_name(), &request.public.v_max)?),
    );
    inputs.insert(
        gamma_bound_name().to_string(),
        field(parse_decimal_string(
            gamma_bound_name(),
            &request.public.gamma_bound,
        )?),
    );
    inputs.insert(
        gravity_name().to_string(),
        field(parse_decimal_string(gravity_name(), &request.public.g_0)?),
    );
    inputs.insert(
        k_sg_name().to_string(),
        field(parse_decimal_string(k_sg_name(), &request.public.k_sg)?),
    );

    // Scalar private inputs
    inputs.insert(
        altitude_name().to_string(),
        field(parse_decimal_string(
            altitude_name(),
            &request.private.initial_altitude,
        )?),
    );
    inputs.insert(
        velocity_name().to_string(),
        field(parse_decimal_string(
            velocity_name(),
            &request.private.initial_velocity,
        )?),
    );
    inputs.insert(
        gamma_name().to_string(),
        field(parse_decimal_string(
            gamma_name(),
            &request.private.initial_flight_path_angle,
        )?),
    );
    inputs.insert(
        mass_input_name().to_string(),
        field(parse_decimal_string(
            mass_input_name(),
            &request.private.vehicle_mass,
        )?),
    );
    inputs.insert(
        sref_name().to_string(),
        field(parse_decimal_string(
            sref_name(),
            &request.private.reference_area,
        )?),
    );
    inputs.insert(
        cd_name().to_string(),
        field(parse_decimal_string(
            cd_name(),
            &request.private.drag_coefficient,
        )?),
    );
    inputs.insert(
        cl_name().to_string(),
        field(parse_decimal_string(
            cl_name(),
            &request.private.lift_coefficient,
        )?),
    );
    inputs.insert(
        rn_name().to_string(),
        field(parse_decimal_string(
            rn_name(),
            &request.private.nose_radius,
        )?),
    );

    // Per-step private inputs
    for step in 0..steps {
        let name = bank_cos_name(step);
        inputs.insert(
            name.clone(),
            field(parse_decimal_string(
                &name,
                &request.private.bank_angle_cosines[step],
            )?),
        );
        let name = sin_gamma_input_name(step);
        inputs.insert(
            name.clone(),
            field(parse_decimal_string(
                &name,
                &request.private.sin_gamma[step],
            )?),
        );
        let name = cos_gamma_input_name(step);
        inputs.insert(
            name.clone(),
            field(parse_decimal_string(
                &name,
                &request.private.cos_gamma[step],
            )?),
        );
        let name = rho_name(step);
        inputs.insert(
            name.clone(),
            field(parse_decimal_string(
                &name,
                &request.private.density_profile[step],
            )?),
        );
    }
    Ok(())
}

impl TryFrom<PrivateReentryThermalRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: PrivateReentryThermalRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, &request)?;
        Ok(inputs)
    }
}

impl TryFrom<&PrivateReentryThermalRequestV1> for WitnessInputs {
    type Error = ZkfError;

    fn try_from(request: &PrivateReentryThermalRequestV1) -> Result<Self, Self::Error> {
        let mut inputs = WitnessInputs::new();
        insert_request_inputs(&mut inputs, request)?;
        Ok(inputs)
    }
}

// ---------------------------------------------------------------------------
// Load / validate public parameters
// ---------------------------------------------------------------------------

fn load_public_parameters(inputs: &WitnessInputs) -> ZkfResult<ReentryPublicParameters> {
    let parameters = ReentryPublicParameters {
        q_max: read_input(inputs, q_max_name())?,
        q_dot_max: read_input(inputs, q_dot_max_name())?,
        h_min: read_input(inputs, h_min_name())?,
        v_max: read_input(inputs, v_max_name())?,
        gamma_bound: read_input(inputs, gamma_bound_name())?,
        g_0: read_input(inputs, gravity_name())?,
        k_sg: read_input(inputs, k_sg_name())?,
    };
    ensure_positive_le(q_max_name(), &parameters.q_max, &q_max_bound())?;
    ensure_positive_le(q_dot_max_name(), &parameters.q_dot_max, &q_dot_max_bound())?;
    ensure_nonnegative_le(h_min_name(), &parameters.h_min, &altitude_bound())?;
    ensure_positive_le(v_max_name(), &parameters.v_max, &velocity_bound_value())?;
    ensure_positive_le(
        gamma_bound_name(),
        &parameters.gamma_bound,
        &gamma_bound_default(),
    )?;
    ensure_positive_le(gravity_name(), &parameters.g_0, &gravity_bound_value())?;
    ensure_positive_le(k_sg_name(), &parameters.k_sg, &k_sg_bound())?;
    Ok(parameters)
}

fn write_public_parameter_support(
    values: &mut BTreeMap<String, FieldElement>,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<()> {
    write_nonnegative_bound_support(
        values,
        q_max_name(),
        &parameters.q_max,
        &q_max_bound(),
        "q_max_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        q_dot_max_name(),
        &parameters.q_dot_max,
        &q_dot_max_bound(),
        "q_dot_max_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        h_min_name(),
        &parameters.h_min,
        &altitude_bound(),
        "h_min_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        v_max_name(),
        &parameters.v_max,
        &velocity_bound_value(),
        "v_max_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        gamma_bound_name(),
        &parameters.gamma_bound,
        &gamma_bound_default(),
        "gamma_bound_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        gravity_name(),
        &parameters.g_0,
        &gravity_bound_value(),
        "gravity_bound",
    )?;
    write_nonnegative_bound_support(
        values,
        k_sg_name(),
        &parameters.k_sg,
        &k_sg_bound(),
        "k_sg_bound",
    )?;
    write_nonzero_inverse_support(values, &parameters.q_max, "q_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.q_dot_max, "q_dot_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.v_max, "v_max_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.gamma_bound, "gamma_bound_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.g_0, "gravity_nonzero")?;
    write_nonzero_inverse_support(values, &parameters.k_sg, "k_sg_nonzero")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Step dynamics computation (off-chain, for witness generation)
// ---------------------------------------------------------------------------

fn compute_step_dynamics(
    h: &BigInt,
    v: &BigInt,
    gamma: &BigInt,
    sin_g: &BigInt,
    cos_g: &BigInt,
    rho: &BigInt,
    bank_cos: &BigInt,
    mass: &BigInt,
    s_ref: &BigInt,
    c_d: &BigInt,
    c_l: &BigInt,
    _r_n: &BigInt,
    _k_sg: &BigInt,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<ReentryStepComputation> {
    let scale = fixed_scale();
    let scale_sq = fixed_scale_squared();

    // Validate trig identity: sin^2 + cos^2 should be close to SCALE^2
    let sin_sq = sin_g * sin_g;
    let cos_sq = cos_g * cos_g;
    let trig_sum = &sin_sq + &cos_sq;
    let trig_residual = &scale_sq - &trig_sum;
    // Allow small residual due to fixed-point truncation
    let trig_residual_bound = &scale * BigInt::from(2u8); // generous tolerance
    if abs_bigint(trig_residual.clone()) > trig_residual_bound {
        return Err(ZkfError::InvalidArtifact(
            "trig identity residual too large".to_string(),
        ));
    }

    // V^2
    let v_sq = v * v;
    ensure_nonnegative_le("v_sq", &v_sq, &v_sq_bound())?;

    // Fixed-point V^2 and V^3 support for the heating model.
    let (v_sq_fp, v_sq_fp_remainder, v_sq_fp_slack) = euclidean_division(&v_sq, &scale)?;
    ensure_nonnegative_le("v_sq_fp", &v_sq_fp, &v_sq_fp_bound())?;
    let v_cubed_numerator = &v_sq_fp * v;
    let (v_cubed_fp, v_cubed_remainder, v_cubed_slack) =
        euclidean_division(&v_cubed_numerator, &scale)?;
    ensure_nonnegative_le("v_cubed_fp", &v_cubed_fp, &v_cubed_fp_bound())?;

    // rho * V^2 / SCALE (intermediate)
    let rho_v_sq_numerator = rho * &v_sq;
    let (rho_v_sq, rho_v_sq_remainder, rho_v_sq_slack) =
        euclidean_division(&rho_v_sq_numerator, &scale)?;

    // Dynamic pressure: q = rho_v_sq / (2 * SCALE)
    let (q_i, q_i_remainder, q_i_slack) = euclidean_division(&rho_v_sq, &(two() * &scale))?;
    ensure_nonnegative_le("q_i", &q_i, &dynamic_pressure_bound())?;

    // Drag: D = q * S_ref * C_D / SCALE^2
    // q is scaled, S_ref is scaled, C_D is scaled, product has SCALE^3, we want SCALE^1
    let drag_numerator = &q_i * s_ref * c_d;
    let (drag_force, drag_remainder, drag_slack) = euclidean_division(&drag_numerator, &scale_sq)?;

    // Lift coefficient product: lift_cos = C_L * cos(sigma) / SCALE
    let lift_cos_numerator = c_l * bank_cos;
    let (lift_cos, lift_cos_remainder, lift_cos_slack) =
        euclidean_division(&lift_cos_numerator, &scale)?;

    // Lift: L = q * S_ref * lift_cos / SCALE^2
    // q is scaled, S_ref is scaled, lift_cos is scaled, product has SCALE^3
    let lift_numerator = &q_i * s_ref * &lift_cos;
    let (lift_force, lift_remainder, lift_slack) = euclidean_division(&lift_numerator, &scale_sq)?;

    // Drag acceleration: D / m (scaled by SCALE to keep fixed-point)
    let drag_accel_numerator = &drag_force * &scale;
    let (drag_accel, drag_accel_remainder, drag_accel_slack) =
        euclidean_division(&drag_accel_numerator, mass)?;

    // Lift acceleration: L / m (scaled)
    let lift_accel_numerator = &lift_force * &scale;
    let (lift_accel, lift_accel_remainder, lift_accel_slack) =
        euclidean_division(&lift_accel_numerator, mass)?;

    // g * sin(gamma) / SCALE
    let g_sin_numerator = &parameters.g_0 * sin_g;
    let (g_sin_gamma, g_sin_gamma_remainder, g_sin_gamma_slack) =
        euclidean_division(&g_sin_numerator, &scale)?;

    // Velocity update: dV = (-drag_accel - g_sin_gamma) * dt / SCALE
    let dv_accel = -&drag_accel - &g_sin_gamma;
    let dv_raw = &dv_accel * &dt_scaled();
    let (dv, dv_remainder, dv_slack) = euclidean_division(&dv_raw, &scale)?;

    // Altitude update: dh = V * sin(gamma) * dt / SCALE^2
    // We compute: v_sin = V * sin(gamma), then dh = v_sin * dt / SCALE^2
    // But actually V * sin(gamma) is product of two scaled values, so:
    //   V * sin(gamma) gives SCALE^2 worth of scaling
    //   dh = V * sin(gamma) * dt / SCALE^2
    let v_sin = v * sin_g;
    let dh_raw = &v_sin * &dt_scaled();
    let (dh, dh_remainder, dh_slack) = euclidean_division(&dh_raw, &scale_sq)?;

    // FPA update: d_gamma = (L/(m*V) - g*cos(gamma)/V) * dt / SCALE
    // We already have lift_accel = L*SCALE/m.
    // lift_over_v = lift_accel * SCALE / V  (gives lift_accel/V in fixed-point)
    let lift_over_v_numerator = &lift_accel * &scale;
    let (lift_over_v, lift_over_v_remainder, lift_over_v_slack) =
        euclidean_division(&lift_over_v_numerator, v)?;

    // g * cos(gamma) / SCALE
    let g_cos_numerator = &parameters.g_0 * cos_g;
    let (g_cos_gamma, g_cos_gamma_remainder, g_cos_gamma_slack) =
        euclidean_division(&g_cos_numerator, &scale)?;

    // gcos_over_v = g_cos_gamma * SCALE / V
    let gcos_over_v_numerator = &g_cos_gamma * &scale;
    let (gcos_over_v, gcos_over_v_remainder, gcos_over_v_slack) =
        euclidean_division(&gcos_over_v_numerator, v)?;

    // dgamma = (lift_over_v - gcos_over_v) * dt / SCALE
    let dgamma_accel = &lift_over_v - &gcos_over_v;
    let dgamma_raw = &dgamma_accel * &dt_scaled();
    let (dgamma, dgamma_remainder, dgamma_slack) = euclidean_division(&dgamma_raw, &scale)?;

    // Next state
    let next_altitude = h + &dh;
    let next_velocity = v + &dv;
    let next_gamma = gamma + &dgamma;

    // Heating rate: q_dot = k_sg * sqrt(rho / r_n) * V^3
    // This is encoded through staged exact divisions so the accepted lane carries
    // the full fixed-point derivation instead of a prover-side hint.
    let rho_over_rn_numerator = rho * &scale;
    let (rho_over_rn_fp, rho_over_rn_remainder, rho_over_rn_slack) =
        euclidean_division(&rho_over_rn_numerator, _r_n)?;
    ensure_nonnegative_le("rho_over_rn_fp", &rho_over_rn_fp, &rho_over_rn_bound())?;

    let sqrt_input = &rho_over_rn_fp * &scale;
    let (sqrt_rho_over_rn_fp, sqrt_rho_over_rn_remainder, sqrt_rho_over_rn_upper_slack) =
        floor_sqrt_support(&sqrt_input)?;
    ensure_nonnegative_le(
        "sqrt_rho_over_rn_fp",
        &sqrt_rho_over_rn_fp,
        &sqrt_rho_over_rn_bound(),
    )?;

    let heating_factor_numerator = _k_sg * &sqrt_rho_over_rn_fp;
    let (heating_factor, heating_factor_remainder, heating_factor_slack) =
        euclidean_division(&heating_factor_numerator, &scale)?;
    ensure_nonnegative_le("heating_factor", &heating_factor, &heating_factor_bound())?;

    let q_dot_numerator = &heating_factor * &v_cubed_fp;
    let (q_dot_i, q_dot_remainder, q_dot_slack) = euclidean_division(&q_dot_numerator, &scale)?;
    ensure_nonnegative_le("q_dot_i", &q_dot_i, &q_dot_max_bound())?;

    // Safety checks
    if q_i > parameters.q_max {
        return Err(ZkfError::InvalidArtifact(
            "dynamic pressure exceeded q_max".to_string(),
        ));
    }
    if q_dot_i > parameters.q_dot_max {
        return Err(ZkfError::InvalidArtifact(
            "heating rate exceeded q_dot_max".to_string(),
        ));
    }
    if next_altitude < parameters.h_min {
        return Err(ZkfError::InvalidArtifact(
            "altitude dropped below h_min".to_string(),
        ));
    }
    if next_velocity > parameters.v_max && next_velocity > zero() {
        // velocity should be decreasing during reentry; check unsigned
    }
    ensure_nonnegative_le("next_altitude", &next_altitude, &altitude_bound())?;

    let q_safety_slack = &parameters.q_max - &q_i;
    let q_dot_safety_slack = &parameters.q_dot_max - &q_dot_i;
    let h_safety_slack = h - &parameters.h_min; // current altitude vs h_min
    let v_safety_slack = &parameters.v_max - v; // v_max - current velocity

    Ok(ReentryStepComputation {
        trig_identity_residual: trig_residual,
        v_sq,
        v_sq_fp,
        v_sq_fp_remainder,
        v_sq_fp_slack,
        v_cubed_fp,
        v_cubed_remainder,
        v_cubed_slack,
        rho_v_sq,
        rho_v_sq_remainder,
        rho_v_sq_slack,
        q_i,
        q_i_remainder,
        q_i_slack,
        drag_force,
        drag_remainder,
        drag_slack,
        lift_cos,
        lift_cos_remainder,
        lift_cos_slack,
        lift_force,
        lift_remainder,
        lift_slack,
        drag_accel,
        drag_accel_remainder,
        drag_accel_slack,
        lift_accel,
        lift_accel_remainder,
        lift_accel_slack,
        g_sin_gamma,
        g_sin_gamma_remainder,
        g_sin_gamma_slack,
        dv_accel,
        dv_raw,
        dv,
        dv_remainder,
        dv_slack,
        v_sin,
        dh_raw,
        dh,
        dh_remainder,
        dh_slack,
        lift_over_v,
        lift_over_v_remainder,
        lift_over_v_slack,
        g_cos_gamma,
        g_cos_gamma_remainder,
        g_cos_gamma_slack,
        gcos_over_v,
        gcos_over_v_remainder,
        gcos_over_v_slack,
        dgamma_accel,
        dgamma_raw,
        dgamma,
        dgamma_remainder,
        dgamma_slack,
        next_altitude,
        next_velocity,
        next_gamma,
        rho_over_rn_fp,
        rho_over_rn_remainder,
        rho_over_rn_slack,
        sqrt_rho_over_rn_fp,
        sqrt_rho_over_rn_remainder,
        sqrt_rho_over_rn_upper_slack,
        heating_factor,
        heating_factor_remainder,
        heating_factor_slack,
        q_dot_i,
        q_dot_remainder,
        q_dot_slack,
        q_safety_slack,
        q_dot_safety_slack,
        h_safety_slack,
        v_safety_slack,
    })
}

// ---------------------------------------------------------------------------
// Sample inputs generator
// ---------------------------------------------------------------------------

fn sample_public_parameters() -> ReentryPublicParameters {
    ReentryPublicParameters {
        q_max: decimal_scaled("800"),
        q_dot_max: decimal_scaled("200"),
        h_min: decimal_scaled("30"),
        v_max: decimal_scaled("7.6"),
        gamma_bound: decimal_scaled("0.35"),
        g_0: decimal_scaled("0.009806"),
        k_sg: decimal_scaled("0.00005"),
    }
}

#[allow(clippy::expect_used)]
fn reentry_sample_inputs_for_steps(steps: usize) -> WitnessInputs {
    let public = sample_public_parameters();
    let scale = fixed_scale();

    // Initial conditions in reduced-order km / km-per-second units.
    let h0 = decimal_scaled("80");
    let v0 = decimal_scaled("7");
    let gamma0 = decimal_scaled("-0.005");

    // Vehicle parameters
    let mass = decimal_scaled("10"); // 10 tonnes
    let s_ref = decimal_scaled("10");
    let c_d = decimal_scaled("1.5");
    let c_l = decimal_scaled("0.5");
    let r_n = decimal_scaled("1");

    // Generate per-step inputs
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gammas = Vec::with_capacity(steps);
    let mut cos_gammas = Vec::with_capacity(steps);
    let mut densities = Vec::with_capacity(steps);

    let mut current_h = h0.clone();
    let mut current_v = v0.clone();
    let mut current_gamma = gamma0.clone();

    for step in 0..steps {
        // Bank angle schedule: start at 60 deg (cos=0.5), linearly reduce to 0 deg (cos=1.0)
        let fraction_done = BigInt::from(step as u64) * &scale / BigInt::from(steps as u64);
        let bank_cos_val = &scale / two() + &fraction_done / two(); // 0.5 -> 1.0

        // Compute sin/cos of current gamma using Taylor series.
        // gamma is a fixed-point value (gamma_real * SCALE).
        // sin(gamma) in fixed-point = gamma_real * SCALE = gamma (first-order Taylor).
        // For better accuracy, use:
        //   sin(x) = x - x^3/6 + x^5/120, where x = gamma/SCALE (real value)
        //   sin_scaled = gamma - gamma^3 / (6 * SCALE^2) + gamma^5 / (120 * SCALE^4)
        // Then compute cos_scaled = isqrt(SCALE^2 - sin_scaled^2) to guarantee identity.

        let gamma_sq = &current_gamma * &current_gamma;
        // gamma^3 / (6 * SCALE^2)
        let gamma_cubed = &gamma_sq * &current_gamma;
        let denom_3 = BigInt::from(6u8) * &fixed_scale_squared();
        let (correction_3, _, _) =
            euclidean_division(&abs_bigint(gamma_cubed.clone()), &denom_3).expect("sin taylor x^3");
        let correction_3_signed = if gamma_cubed.sign() == Sign::Minus {
            -&correction_3
        } else {
            correction_3.clone()
        };

        // sin(gamma) ~ gamma - gamma^3/6SCALE^2
        let sin_val = &current_gamma - &correction_3_signed;

        // Clamp sin_val to trig bound
        let sin_val = if sin_val > trig_bound() {
            trig_bound()
        } else if sin_val < -trig_bound() {
            -trig_bound()
        } else {
            sin_val
        };

        // cos = sqrt(SCALE^2 - sin^2) -- guarantees sin^2 + cos^2 + residual = SCALE^2
        // with residual = SCALE^2 - sin^2 - cos^2 >= 0 and small (just the floor remainder)
        let sin_sq = &sin_val * &sin_val;
        let cos_sq_target = &fixed_scale_squared() - &sin_sq;
        let cos_val = if cos_sq_target <= zero() {
            zero()
        } else {
            bigint_isqrt_floor(&cos_sq_target)
        };

        // Atmospheric density proxy with altitude in kilometers.
        let h_scale_height = decimal_scaled("7.2");
        let rho_0 = decimal_scaled("1.225");
        // h_over_H in fixed-point = current_h * SCALE / h_scale_height
        let (h_over_h_fp, _, _) = euclidean_division(&(&current_h * &scale), &h_scale_height)
            .expect("h_over_H fixed-point");
        // Now h_over_h_fp is h/H * SCALE (e.g., at 120km: ~16.67 * SCALE)
        // exp(-x) where x = h_over_h_fp / SCALE using (1 - x/N)^N approximation
        // with N = 256 sub-steps for adequate precision at large x
        let exp_n: u64 = 256;
        let mut exp_val = scale.clone(); // starts at 1.0 (scaled)
        // x_per_step = h_over_h_fp / exp_n  (this is in SCALE units)
        let (x_per_step, _, _) =
            euclidean_division(&h_over_h_fp, &BigInt::from(exp_n)).expect("x_per_step");
        for _ in 0..exp_n {
            // exp_val *= (SCALE - x_per_step) / SCALE
            let factor = &scale - &x_per_step;
            if factor <= zero() {
                exp_val = zero();
                break;
            }
            let (new_val, _, _) =
                euclidean_division(&(&exp_val * &factor), &scale).expect("exp decay step");
            exp_val = new_val;
            if exp_val <= zero() {
                exp_val = zero();
                break;
            }
        }
        // rho = rho_0 * exp_val / SCALE
        let (rho_val, _, _) =
            euclidean_division(&(&rho_0 * &exp_val), &scale).expect("rho computation");
        // Clamp rho to be at least a tiny positive value for division safety
        let rho_val = if rho_val <= zero() { one() } else { rho_val };

        bank_cosines.push(bank_cos_val.clone());
        sin_gammas.push(sin_val.clone());
        cos_gammas.push(cos_val.clone());
        densities.push(rho_val.clone());

        // Forward-propagate state using the SAME compute_step_dynamics function
        // that the witness generator uses. This guarantees arithmetic consistency.
        let step_result = compute_step_dynamics(
            &current_h,
            &current_v,
            &current_gamma,
            &sin_val,
            &cos_val,
            &rho_val,
            &bank_cos_val,
            &mass,
            &s_ref,
            &c_d,
            &c_l,
            &r_n,
            &public.k_sg,
            &public,
        )
        .expect("sample trajectory step dynamics must succeed");

        current_h = step_result.next_altitude.clone();
        current_v = step_result.next_velocity.clone();
        current_gamma = step_result.next_gamma.clone();
    }

    let mut inputs = WitnessInputs::new();

    // Public inputs
    inputs.insert(q_max_name().to_string(), field_ref(&public.q_max));
    inputs.insert(q_dot_max_name().to_string(), field_ref(&public.q_dot_max));
    inputs.insert(h_min_name().to_string(), field_ref(&public.h_min));
    inputs.insert(v_max_name().to_string(), field_ref(&public.v_max));
    inputs.insert(
        gamma_bound_name().to_string(),
        field_ref(&public.gamma_bound),
    );
    inputs.insert(gravity_name().to_string(), field_ref(&public.g_0));
    inputs.insert(k_sg_name().to_string(), field_ref(&public.k_sg));

    // Scalar private inputs
    inputs.insert(altitude_name().to_string(), field_ref(&h0));
    inputs.insert(velocity_name().to_string(), field_ref(&v0));
    inputs.insert(gamma_name().to_string(), field_ref(&gamma0));
    inputs.insert(mass_input_name().to_string(), field_ref(&mass));
    inputs.insert(sref_name().to_string(), field_ref(&s_ref));
    inputs.insert(cd_name().to_string(), field_ref(&c_d));
    inputs.insert(cl_name().to_string(), field_ref(&c_l));
    inputs.insert(rn_name().to_string(), field_ref(&r_n));

    // Per-step private inputs
    for step in 0..steps {
        inputs.insert(bank_cos_name(step), field_ref(&bank_cosines[step]));
        inputs.insert(sin_gamma_input_name(step), field_ref(&sin_gammas[step]));
        inputs.insert(cos_gamma_input_name(step), field_ref(&cos_gammas[step]));
        inputs.insert(rho_name(step), field_ref(&densities[step]));
    }

    inputs
}

#[doc(hidden)]
pub fn private_reentry_thermal_sample_request_with_steps(
    steps: usize,
) -> ZkfResult<PrivateReentryThermalRequestV1> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "reentry thermal sample request requires at least one integration step".to_string(),
        ));
    }
    let public = sample_public_parameters();

    let h0 = decimal_scaled("80");
    let v0 = decimal_scaled("7");
    let gamma0 = decimal_scaled("-0.02");
    let mass = decimal_scaled("10");
    let s_ref = decimal_scaled("10");
    let c_d = decimal_scaled("1.5");
    let c_l = decimal_scaled("0.5");
    let r_n = decimal_scaled("1");

    // Regenerate per-step from the sample_inputs helper
    let sample = reentry_sample_inputs_for_steps(steps);
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gamma_vec = Vec::with_capacity(steps);
    let mut cos_gamma_vec = Vec::with_capacity(steps);
    let mut density_vec = Vec::with_capacity(steps);

    for step in 0..steps {
        bank_cosines.push(scaled_bigint_to_decimal_string(
            &sample.get(&bank_cos_name(step)).unwrap().as_bigint(),
        ));
        sin_gamma_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&sin_gamma_input_name(step)).unwrap().as_bigint(),
        ));
        cos_gamma_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&cos_gamma_input_name(step)).unwrap().as_bigint(),
        ));
        density_vec.push(scaled_bigint_to_decimal_string(
            &sample.get(&rho_name(step)).unwrap().as_bigint(),
        ));
    }

    Ok(PrivateReentryThermalRequestV1 {
        private: ReentryPrivateInputsV1 {
            initial_altitude: scaled_bigint_to_decimal_string(&h0),
            initial_velocity: scaled_bigint_to_decimal_string(&v0),
            initial_flight_path_angle: scaled_bigint_to_decimal_string(&gamma0),
            vehicle_mass: scaled_bigint_to_decimal_string(&mass),
            reference_area: scaled_bigint_to_decimal_string(&s_ref),
            drag_coefficient: scaled_bigint_to_decimal_string(&c_d),
            lift_coefficient: scaled_bigint_to_decimal_string(&c_l),
            nose_radius: scaled_bigint_to_decimal_string(&r_n),
            bank_angle_cosines: bank_cosines,
            sin_gamma: sin_gamma_vec,
            cos_gamma: cos_gamma_vec,
            density_profile: density_vec,
        },
        public: ReentryPublicInputsV1 {
            q_max: scaled_bigint_to_decimal_string(&public.q_max),
            q_dot_max: scaled_bigint_to_decimal_string(&public.q_dot_max),
            h_min: scaled_bigint_to_decimal_string(&public.h_min),
            v_max: scaled_bigint_to_decimal_string(&public.v_max),
            gamma_bound: scaled_bigint_to_decimal_string(&public.gamma_bound),
            g_0: scaled_bigint_to_decimal_string(&public.g_0),
            k_sg: scaled_bigint_to_decimal_string(&public.k_sg),
            step_count: steps,
        },
    })
}

#[doc(hidden)]
pub fn reentry_mission_pack_sample_with_steps(steps: usize) -> ZkfResult<ReentryMissionPackV1> {
    let request = private_reentry_thermal_sample_request_with_steps(steps)?;
    Ok(ReentryMissionPackV1 {
        private: request.private,
        public_envelope: request.public.into(),
        private_model_commitments: ReentryPrivateModelCommitmentsV1 {
            mission_id: format!("sample-reentry-{steps}-step"),
            aerodynamic_model_commitment: "sample-aero-commitment".to_string(),
            thermal_model_commitment: "sample-thermal-commitment".to_string(),
            guidance_policy_commitment: "sample-guidance-commitment".to_string(),
        },
    })
}

fn sample_sine_from_gamma(gamma: &BigInt) -> BigInt {
    let gamma_cubed = gamma * gamma * gamma;
    let denom = BigInt::from(6u8) * fixed_scale_squared();
    let correction = if denom == zero() {
        zero()
    } else {
        let (quotient, _, _) = euclidean_division(&abs_bigint(gamma_cubed.clone()), &denom)
            .expect("sample sine correction division");
        if gamma_cubed.sign() == Sign::Minus {
            -quotient
        } else {
            quotient
        }
    };
    let sin = gamma - correction;
    if sin > trig_bound() {
        trig_bound()
    } else if sin < -trig_bound() {
        -trig_bound()
    } else {
        sin
    }
}

fn sample_density_from_altitude(altitude: &BigInt) -> BigInt {
    let scale = fixed_scale();
    let h_scale_height = decimal_scaled("7.2");
    let rho_0 = decimal_scaled("1.225");
    let (h_over_h_fp, _, _) =
        euclidean_division(&(altitude * &scale), &h_scale_height).expect("sample h_over_H");
    let exp_n: u64 = 256;
    let mut exp_val = scale.clone();
    let (x_per_step, _, _) =
        euclidean_division(&h_over_h_fp, &BigInt::from(exp_n)).expect("sample x_per_step");
    for _ in 0..exp_n {
        let factor = &scale - &x_per_step;
        if factor <= zero() {
            exp_val = zero();
            break;
        }
        let (new_val, _, _) =
            euclidean_division(&(&exp_val * &factor), &scale).expect("sample exp decay step");
        exp_val = new_val;
    }
    let (density, _, _) = euclidean_division(&(&rho_0 * &exp_val), &scale).expect("sample rho");
    if density > density_bound() {
        density_bound()
    } else {
        density
    }
}

fn public_parameters_from_envelope(
    envelope: &ReentryPublicEnvelopeV1,
) -> ZkfResult<ReentryPublicParameters> {
    let parameters = ReentryPublicParameters {
        q_max: parse_decimal_string(q_max_name(), &envelope.q_max)?,
        q_dot_max: parse_decimal_string(q_dot_max_name(), &envelope.q_dot_max)?,
        h_min: parse_decimal_string(h_min_name(), &envelope.h_min)?,
        v_max: parse_decimal_string(v_max_name(), &envelope.v_max)?,
        gamma_bound: parse_decimal_string(gamma_bound_name(), &envelope.gamma_bound)?,
        g_0: parse_decimal_string(gravity_name(), &envelope.g_0)?,
        k_sg: parse_decimal_string(k_sg_name(), &envelope.k_sg)?,
    };
    ensure_positive_le(q_max_name(), &parameters.q_max, &q_max_bound())?;
    ensure_positive_le(q_dot_max_name(), &parameters.q_dot_max, &q_dot_max_bound())?;
    ensure_nonnegative_le(h_min_name(), &parameters.h_min, &altitude_bound())?;
    ensure_positive_le(v_max_name(), &parameters.v_max, &velocity_bound_value())?;
    ensure_positive_le(
        gamma_bound_name(),
        &parameters.gamma_bound,
        &gamma_bound_default(),
    )?;
    ensure_positive_le(gravity_name(), &parameters.g_0, &gravity_bound_value())?;
    ensure_positive_le(k_sg_name(), &parameters.k_sg, &k_sg_bound())?;
    Ok(parameters)
}

fn interpolate_piecewise_scaled(
    value: &BigInt,
    lower: &BigInt,
    upper: &BigInt,
    start: &BigInt,
    end: &BigInt,
    label: &str,
) -> ZkfResult<BigInt> {
    if upper < lower {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} band has altitude/gamma end below start"
        )));
    }
    if value < lower || value > upper {
        return Err(ZkfError::InvalidArtifact(format!(
            "{label} value {} is outside the selected band [{}, {}]",
            scaled_bigint_to_decimal_string(value),
            scaled_bigint_to_decimal_string(lower),
            scaled_bigint_to_decimal_string(upper)
        )));
    }
    if upper == lower {
        return Ok(start.clone());
    }
    let span = upper - lower;
    let offset = value - lower;
    let delta = end - start;
    let (scaled_delta, _, _) = euclidean_division(&(&offset * &delta), &span)?;
    Ok(start + scaled_delta)
}

fn interpolate_atmosphere_density(
    altitude: &BigInt,
    bands: &[ReentryAtmosphereBandRowV1],
) -> ZkfResult<BigInt> {
    for band in bands {
        let altitude_start =
            parse_decimal_string("atmosphere.altitude_start", &band.altitude_start)?;
        let altitude_end = parse_decimal_string("atmosphere.altitude_end", &band.altitude_end)?;
        if altitude < &altitude_start || altitude > &altitude_end {
            continue;
        }
        let density_start = parse_decimal_string("atmosphere.density_start", &band.density_start)?;
        let density_end = parse_decimal_string("atmosphere.density_end", &band.density_end)?;
        return interpolate_piecewise_scaled(
            altitude,
            &altitude_start,
            &altitude_end,
            &density_start,
            &density_end,
            "atmosphere",
        );
    }
    Err(ZkfError::InvalidArtifact(format!(
        "altitude {} is outside the supplied atmosphere bands",
        scaled_bigint_to_decimal_string(altitude)
    )))
}

fn interpolate_sine_from_gamma(
    gamma: &BigInt,
    bands: &[ReentrySineBandRowV1],
) -> ZkfResult<BigInt> {
    for band in bands {
        let gamma_start = parse_decimal_string("sine.gamma_start", &band.gamma_start)?;
        let gamma_end = parse_decimal_string("sine.gamma_end", &band.gamma_end)?;
        if gamma < &gamma_start || gamma > &gamma_end {
            continue;
        }
        let sine_start = parse_decimal_string("sine.sine_start", &band.sine_start)?;
        let sine_end = parse_decimal_string("sine.sine_end", &band.sine_end)?;
        let interpolated = interpolate_piecewise_scaled(
            gamma,
            &gamma_start,
            &gamma_end,
            &sine_start,
            &sine_end,
            "sine",
        )?;
        return Ok(if interpolated > trig_bound() {
            trig_bound()
        } else if interpolated < -trig_bound() {
            -trig_bound()
        } else {
            interpolated
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "flight-path angle {} is outside the supplied sine bands",
        scaled_bigint_to_decimal_string(gamma)
    )))
}

pub fn materialize_private_reentry_request_v1_from_v2(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<PrivateReentryThermalRequestV1> {
    let steps = mission_pack.public_envelope.certified_horizon_steps;
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "reentry mission pack v2 must use a nonzero certified horizon".to_string(),
        ));
    }
    if mission_pack.private.bank_angle_cosines.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "reentry mission pack v2 certified_horizon_steps={} does not match bank_angle_cosines length={}",
            steps,
            mission_pack.private.bank_angle_cosines.len()
        )));
    }
    if mission_pack.private.atmosphere_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "reentry mission pack v2 must supply at least one atmosphere band".to_string(),
        ));
    }
    if mission_pack.private.sine_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "reentry mission pack v2 must supply at least one sine band".to_string(),
        ));
    }
    if mission_pack.private.abort_corridor_bands.is_empty() {
        return Err(ZkfError::InvalidArtifact(
            "reentry mission pack v2 must supply at least one abort corridor band".to_string(),
        ));
    }

    let public = public_parameters_from_envelope(&mission_pack.public_envelope)?;
    let mass = parse_decimal_string(mass_input_name(), &mission_pack.private.vehicle_mass)?;
    let s_ref = parse_decimal_string(sref_name(), &mission_pack.private.reference_area)?;
    let c_d = parse_decimal_string(cd_name(), &mission_pack.private.drag_coefficient)?;
    let c_l = parse_decimal_string(cl_name(), &mission_pack.private.lift_coefficient)?;
    let r_n = parse_decimal_string(rn_name(), &mission_pack.private.nose_radius)?;
    let abort_q_trigger = parse_decimal_string(
        "abort_thresholds.q_trigger_min",
        &mission_pack.private.abort_thresholds.q_trigger_min,
    )?;
    let abort_q_dot_trigger = parse_decimal_string(
        "abort_thresholds.q_dot_trigger_min",
        &mission_pack.private.abort_thresholds.q_dot_trigger_min,
    )?;
    let abort_altitude_floor = parse_decimal_string(
        "abort_thresholds.altitude_floor",
        &mission_pack.private.abort_thresholds.altitude_floor,
    )?;
    let abort_velocity_ceiling = parse_decimal_string(
        "abort_thresholds.velocity_ceiling",
        &mission_pack.private.abort_thresholds.velocity_ceiling,
    )?;

    let mut current_h =
        parse_decimal_string(altitude_name(), &mission_pack.private.initial_altitude)?;
    let mut current_v =
        parse_decimal_string(velocity_name(), &mission_pack.private.initial_velocity)?;
    let mut current_gamma = parse_decimal_string(
        gamma_name(),
        &mission_pack.private.initial_flight_path_angle,
    )?;
    let mut density_profile = Vec::with_capacity(steps);
    let mut sin_gamma = Vec::with_capacity(steps);
    let mut cos_gamma = Vec::with_capacity(steps);

    for step in 0..steps {
        let bank_cos = parse_decimal_string(
            &bank_cos_name(step),
            &mission_pack.private.bank_angle_cosines[step],
        )?;
        let rho =
            interpolate_atmosphere_density(&current_h, &mission_pack.private.atmosphere_bands)?;
        let sin_g = interpolate_sine_from_gamma(&current_gamma, &mission_pack.private.sine_bands)?;
        let cos_sq_target = fixed_scale_squared() - (&sin_g * &sin_g);
        if cos_sq_target < zero() {
            return Err(ZkfError::InvalidArtifact(format!(
                "reentry mission pack v2 produced an invalid cosine support value at step {step}"
            )));
        }
        let cos_g = bigint_isqrt_floor(&cos_sq_target);
        let step_result = compute_step_dynamics(
            &current_h,
            &current_v,
            &current_gamma,
            &sin_g,
            &cos_g,
            &rho,
            &bank_cos,
            &mass,
            &s_ref,
            &c_d,
            &c_l,
            &r_n,
            &public.k_sg,
            &public,
        )?;

        if step_result.q_i >= abort_q_trigger
            || step_result.q_dot_i >= abort_q_dot_trigger
            || step_result.next_altitude <= abort_altitude_floor
            || step_result.next_velocity >= abort_velocity_ceiling
        {
            return Err(ZkfError::InvalidArtifact(format!(
                "reentry mission pack v2 triggered the abort envelope at step {step}, but the accepted theorem-first lane still rejects abort-branch materialization"
            )));
        }

        density_profile.push(scaled_bigint_to_decimal_string(&rho));
        sin_gamma.push(scaled_bigint_to_decimal_string(&sin_g));
        cos_gamma.push(scaled_bigint_to_decimal_string(&cos_g));
        current_h = step_result.next_altitude;
        current_v = step_result.next_velocity;
        current_gamma = step_result.next_gamma;
    }

    Ok(PrivateReentryThermalRequestV1 {
        private: ReentryPrivateInputsV1 {
            initial_altitude: mission_pack.private.initial_altitude.clone(),
            initial_velocity: mission_pack.private.initial_velocity.clone(),
            initial_flight_path_angle: mission_pack.private.initial_flight_path_angle.clone(),
            vehicle_mass: mission_pack.private.vehicle_mass.clone(),
            reference_area: mission_pack.private.reference_area.clone(),
            drag_coefficient: mission_pack.private.drag_coefficient.clone(),
            lift_coefficient: mission_pack.private.lift_coefficient.clone(),
            nose_radius: mission_pack.private.nose_radius.clone(),
            bank_angle_cosines: mission_pack.private.bank_angle_cosines.clone(),
            sin_gamma,
            cos_gamma,
            density_profile,
        },
        public: mission_pack.public_envelope.clone().into(),
    })
}

// ---------------------------------------------------------------------------
// Accepted RK4 kernel groundwork
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReentryAcceptedStageDynamics {
    rho: BigInt,
    sin_gamma: BigInt,
    cos_gamma: BigInt,
    q_i: BigInt,
    q_dot_i: BigInt,
    dh: BigInt,
    dx: BigInt,
    dv: BigInt,
    dgamma: BigInt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReentryAcceptedStepResult {
    current_altitude: BigInt,
    current_downrange: BigInt,
    current_velocity: BigInt,
    current_gamma: BigInt,
    current_heat: BigInt,
    current_abort_latch: bool,
    stage_q_max: BigInt,
    stage_q_dot_max: BigInt,
    next_altitude: BigInt,
    next_downrange: BigInt,
    next_velocity: BigInt,
    next_gamma: BigInt,
    next_heat: BigInt,
    abort_triggered: bool,
    next_abort_latch: bool,
}

fn accepted_parse_decimal_string(name: &str, value: &str) -> ZkfResult<BigInt> {
    if value.trim().is_empty() {
        return Err(ZkfError::Serialization(format!("{name} must not be empty")));
    }
    Ok(accepted_decimal_scaled(value))
}

fn accepted_parse_positive_nonzero_decimal_string(name: &str, value: &str) -> ZkfResult<BigInt> {
    let accepted = accepted_parse_decimal_string(name, value)?;
    if accepted > zero() {
        return Ok(accepted);
    }
    let legacy = parse_decimal_string(name, value)?;
    if legacy > zero() {
        return Ok(one());
    }
    Err(ZkfError::Serialization(format!(
        "{name} must remain positive after accepted fixed-point quantization"
    )))
}

fn accepted_public_parameters_from_envelope(
    envelope: &ReentryPublicEnvelopeV1,
) -> ZkfResult<ReentryPublicParameters> {
    let parameters = ReentryPublicParameters {
        q_max: accepted_parse_decimal_string(q_max_name(), &envelope.q_max)?,
        q_dot_max: accepted_parse_decimal_string(q_dot_max_name(), &envelope.q_dot_max)?,
        h_min: accepted_parse_decimal_string(h_min_name(), &envelope.h_min)?,
        v_max: accepted_parse_decimal_string(v_max_name(), &envelope.v_max)?,
        gamma_bound: accepted_parse_decimal_string(gamma_bound_name(), &envelope.gamma_bound)?,
        g_0: accepted_parse_decimal_string(gravity_name(), &envelope.g_0)?,
        k_sg: accepted_parse_positive_nonzero_decimal_string(k_sg_name(), &envelope.k_sg)?,
    };
    Ok(parameters)
}

fn accepted_interpolate_atmosphere_density(
    altitude: &BigInt,
    bands: &[ReentryAtmosphereBandRowV1],
) -> ZkfResult<BigInt> {
    for band in bands {
        let altitude_start =
            accepted_parse_decimal_string("atmosphere.altitude_start", &band.altitude_start)?;
        let altitude_end =
            accepted_parse_decimal_string("atmosphere.altitude_end", &band.altitude_end)?;
        if altitude < &altitude_start || altitude > &altitude_end {
            continue;
        }
        let density_start =
            accepted_parse_decimal_string("atmosphere.density_start", &band.density_start)?;
        let density_end =
            accepted_parse_decimal_string("atmosphere.density_end", &band.density_end)?;
        return interpolate_piecewise_scaled(
            altitude,
            &altitude_start,
            &altitude_end,
            &density_start,
            &density_end,
            "accepted-atmosphere",
        );
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted RK4 altitude {} is outside the supplied atmosphere bands",
        accepted_scaled_bigint_to_decimal_string(altitude)
    )))
}

fn accepted_interpolate_sine_from_gamma(
    gamma: &BigInt,
    bands: &[ReentrySineBandRowV1],
) -> ZkfResult<BigInt> {
    for band in bands {
        let gamma_start = accepted_parse_decimal_string("sine.gamma_start", &band.gamma_start)?;
        let gamma_end = accepted_parse_decimal_string("sine.gamma_end", &band.gamma_end)?;
        if gamma < &gamma_start || gamma > &gamma_end {
            continue;
        }
        let sine_start = accepted_parse_decimal_string("sine.sine_start", &band.sine_start)?;
        let sine_end = accepted_parse_decimal_string("sine.sine_end", &band.sine_end)?;
        let interpolated = interpolate_piecewise_scaled(
            gamma,
            &gamma_start,
            &gamma_end,
            &sine_start,
            &sine_end,
            "accepted-sine",
        )?;
        let bound = accepted_scale();
        return Ok(if interpolated > bound {
            bound
        } else if interpolated < -bound.clone() {
            -bound
        } else {
            interpolated
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted RK4 flight-path angle {} is outside the supplied sine bands",
        accepted_scaled_bigint_to_decimal_string(gamma)
    )))
}

fn accepted_select_abort_corridor_row<'a>(
    altitude: &BigInt,
    bands: &'a [ReentryAbortCorridorBandRowV1],
) -> ZkfResult<&'a ReentryAbortCorridorBandRowV1> {
    for band in bands {
        let altitude_start =
            accepted_parse_decimal_string("abort_corridor.altitude_start", &band.altitude_start)?;
        let altitude_end =
            accepted_parse_decimal_string("abort_corridor.altitude_end", &band.altitude_end)?;
        if altitude >= &altitude_start && altitude <= &altitude_end {
            return Ok(band);
        }
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted RK4 abort corridor did not cover altitude {}",
        accepted_scaled_bigint_to_decimal_string(altitude)
    )))
}

#[allow(clippy::too_many_arguments)]
fn accepted_stage_dynamics(
    altitude: &BigInt,
    velocity: &BigInt,
    gamma: &BigInt,
    bank_cos: &BigInt,
    mass: &BigInt,
    s_ref: &BigInt,
    c_d: &BigInt,
    c_l: &BigInt,
    r_n: &BigInt,
    atmosphere_bands: &[ReentryAtmosphereBandRowV1],
    sine_bands: &[ReentrySineBandRowV1],
    parameters: &ReentryPublicParameters,
) -> ZkfResult<ReentryAcceptedStageDynamics> {
    let scale = accepted_scale();
    let scale_sq = accepted_scale_squared();

    let rho = accepted_interpolate_atmosphere_density(altitude, atmosphere_bands)?;
    let sin_gamma = accepted_interpolate_sine_from_gamma(gamma, sine_bands)?;
    let cos_sq_target = &scale_sq - (&sin_gamma * &sin_gamma);
    if cos_sq_target < zero() {
        return Err(ZkfError::InvalidArtifact(
            "accepted RK4 cosine support underflowed".to_string(),
        ));
    }
    let cos_gamma = bigint_isqrt_floor(&cos_sq_target);

    let v_sq = velocity * velocity;
    let (rho_v_sq, _, _) = euclidean_division(&(rho.clone() * &v_sq), &scale)?;
    let (q_i, _, _) = euclidean_division(&rho_v_sq, &(two() * &scale))?;

    let drag_numerator = &q_i * s_ref * c_d;
    let (drag_force, _, _) = euclidean_division(&drag_numerator, &scale_sq)?;

    let lift_cos_numerator = c_l * bank_cos;
    let (lift_cos, _, _) = euclidean_division(&lift_cos_numerator, &scale)?;

    let lift_numerator = &q_i * s_ref * &lift_cos;
    let (lift_force, _, _) = euclidean_division(&lift_numerator, &scale_sq)?;

    let (drag_accel, _, _) = euclidean_division(&(&drag_force * &scale), mass)?;
    let (lift_accel, _, _) = euclidean_division(&(&lift_force * &scale), mass)?;
    let (g_sin_gamma, _, _) = euclidean_division(&(&parameters.g_0 * &sin_gamma), &scale)?;
    let (g_cos_gamma, _, _) = euclidean_division(&(&parameters.g_0 * &cos_gamma), &scale)?;

    let dv = -&drag_accel - &g_sin_gamma;
    let (dh, _, _) = euclidean_division(&(velocity * &sin_gamma), &scale)?;
    let (dx, _, _) = euclidean_division(&(velocity * &cos_gamma), &scale)?;
    let (lift_over_v, _, _) = euclidean_division(&(&lift_accel * &scale), velocity)?;
    let (gcos_over_v, _, _) = euclidean_division(&(&g_cos_gamma * &scale), velocity)?;
    let dgamma = &lift_over_v - &gcos_over_v;

    let (v_sq_fp, _, _) = euclidean_division(&v_sq, &scale)?;
    let (v_cubed_fp, _, _) = euclidean_division(&(&v_sq_fp * velocity), &scale)?;
    let (rho_over_rn_fp, _, _) = euclidean_division(&(rho.clone() * &scale), r_n)?;
    let sqrt_input = &rho_over_rn_fp * &scale;
    let (sqrt_rho_over_rn_fp, _, _) = floor_sqrt_support(&sqrt_input)?;
    let (heating_factor, _, _) =
        euclidean_division(&(&parameters.k_sg * &sqrt_rho_over_rn_fp), &scale)?;
    let (q_dot_i, _, _) = euclidean_division(&(&heating_factor * &v_cubed_fp), &scale)?;

    Ok(ReentryAcceptedStageDynamics {
        rho,
        sin_gamma,
        cos_gamma,
        q_i,
        q_dot_i,
        dh,
        dx,
        dv,
        dgamma,
    })
}

fn accepted_half_step(value: &BigInt) -> ZkfResult<BigInt> {
    let (half, _, _) = euclidean_division(value, &BigInt::from(2u8))?;
    Ok(half)
}

fn accepted_sixth_step(value: &BigInt) -> ZkfResult<BigInt> {
    let (sixth, _, _) = euclidean_division(value, &BigInt::from(6u8))?;
    Ok(sixth)
}

fn accepted_stage_max(values: &[&BigInt]) -> BigInt {
    values.iter().skip(1).fold(values[0].clone(), |acc, value| {
        if *value > &acc { (*value).clone() } else { acc }
    })
}

fn simulate_reentry_rk4_step(
    altitude: &BigInt,
    downrange: &BigInt,
    velocity: &BigInt,
    gamma: &BigInt,
    cumulative_heat: &BigInt,
    abort_latch: bool,
    bank_cos: &BigInt,
    mission_pack: &ReentryMissionPackV2,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<ReentryAcceptedStepResult> {
    let mass =
        accepted_parse_decimal_string(mass_input_name(), &mission_pack.private.vehicle_mass)?;
    let s_ref = accepted_parse_decimal_string(sref_name(), &mission_pack.private.reference_area)?;
    let c_d = accepted_parse_decimal_string(cd_name(), &mission_pack.private.drag_coefficient)?;
    let c_l = accepted_parse_decimal_string(cl_name(), &mission_pack.private.lift_coefficient)?;
    let r_n = accepted_parse_decimal_string(rn_name(), &mission_pack.private.nose_radius)?;

    let k1 = accepted_stage_dynamics(
        altitude,
        velocity,
        gamma,
        bank_cos,
        &mass,
        &s_ref,
        &c_d,
        &c_l,
        &r_n,
        &mission_pack.private.atmosphere_bands,
        &mission_pack.private.sine_bands,
        parameters,
    )?;
    let h2 = altitude + accepted_half_step(&k1.dh)?;
    let x2 = downrange + accepted_half_step(&k1.dx)?;
    let v2 = velocity + accepted_half_step(&k1.dv)?;
    let g2 = gamma + accepted_half_step(&k1.dgamma)?;
    let heat2 = cumulative_heat + accepted_half_step(&k1.q_dot_i)?;

    let k2 = accepted_stage_dynamics(
        &h2,
        &v2,
        &g2,
        bank_cos,
        &mass,
        &s_ref,
        &c_d,
        &c_l,
        &r_n,
        &mission_pack.private.atmosphere_bands,
        &mission_pack.private.sine_bands,
        parameters,
    )?;
    let h3 = altitude + accepted_half_step(&k2.dh)?;
    let x3 = downrange + accepted_half_step(&k2.dx)?;
    let v3 = velocity + accepted_half_step(&k2.dv)?;
    let g3 = gamma + accepted_half_step(&k2.dgamma)?;
    let heat3 = cumulative_heat + accepted_half_step(&k2.q_dot_i)?;

    let _ = (x2, x3, heat2, heat3);

    let k3 = accepted_stage_dynamics(
        &h3,
        &v3,
        &g3,
        bank_cos,
        &mass,
        &s_ref,
        &c_d,
        &c_l,
        &r_n,
        &mission_pack.private.atmosphere_bands,
        &mission_pack.private.sine_bands,
        parameters,
    )?;
    let h4 = altitude + &k3.dh;
    let v4 = velocity + &k3.dv;
    let g4 = gamma + &k3.dgamma;

    let k4 = accepted_stage_dynamics(
        &h4,
        &v4,
        &g4,
        bank_cos,
        &mass,
        &s_ref,
        &c_d,
        &c_l,
        &r_n,
        &mission_pack.private.atmosphere_bands,
        &mission_pack.private.sine_bands,
        parameters,
    )?;

    let weighted = |k1v: &BigInt, k2v: &BigInt, k3v: &BigInt, k4v: &BigInt| -> ZkfResult<BigInt> {
        accepted_sixth_step(&(k1v + (BigInt::from(2u8) * k2v) + (BigInt::from(2u8) * k3v) + k4v))
    };

    let next_altitude = altitude + weighted(&k1.dh, &k2.dh, &k3.dh, &k4.dh)?;
    let next_downrange = downrange + weighted(&k1.dx, &k2.dx, &k3.dx, &k4.dx)?;
    let next_velocity = velocity + weighted(&k1.dv, &k2.dv, &k3.dv, &k4.dv)?;
    let next_gamma = gamma + weighted(&k1.dgamma, &k2.dgamma, &k3.dgamma, &k4.dgamma)?;
    let next_heat = cumulative_heat + weighted(&k1.q_dot_i, &k2.q_dot_i, &k3.q_dot_i, &k4.q_dot_i)?;

    let stage_q_max = accepted_stage_max(&[&k1.q_i, &k2.q_i, &k3.q_i, &k4.q_i]);
    let stage_q_dot_max = accepted_stage_max(&[&k1.q_dot_i, &k2.q_dot_i, &k3.q_dot_i, &k4.q_dot_i]);

    let abort_q_trigger = accepted_parse_decimal_string(
        "abort_thresholds.q_trigger_min",
        &mission_pack.private.abort_thresholds.q_trigger_min,
    )?;
    let abort_q_dot_trigger = accepted_parse_decimal_string(
        "abort_thresholds.q_dot_trigger_min",
        &mission_pack.private.abort_thresholds.q_dot_trigger_min,
    )?;
    let abort_altitude_floor = accepted_parse_decimal_string(
        "abort_thresholds.altitude_floor",
        &mission_pack.private.abort_thresholds.altitude_floor,
    )?;
    let abort_velocity_ceiling = accepted_parse_decimal_string(
        "abort_thresholds.velocity_ceiling",
        &mission_pack.private.abort_thresholds.velocity_ceiling,
    )?;

    let abort_triggered = !abort_latch
        && (stage_q_max >= abort_q_trigger
            || stage_q_dot_max >= abort_q_dot_trigger
            || next_altitude <= abort_altitude_floor
            || next_velocity >= abort_velocity_ceiling);
    let next_abort_latch = abort_latch || abort_triggered;

    if next_abort_latch {
        let corridor = accepted_select_abort_corridor_row(
            &next_altitude,
            &mission_pack.private.abort_corridor_bands,
        )?;
        let velocity_min =
            accepted_parse_decimal_string("abort_corridor.velocity_min", &corridor.velocity_min)?;
        let velocity_max =
            accepted_parse_decimal_string("abort_corridor.velocity_max", &corridor.velocity_max)?;
        let gamma_min =
            accepted_parse_decimal_string("abort_corridor.gamma_min", &corridor.gamma_min)?;
        let gamma_max =
            accepted_parse_decimal_string("abort_corridor.gamma_max", &corridor.gamma_max)?;
        if next_velocity < velocity_min || next_velocity > velocity_max {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 abort corridor velocity bounds failed".to_string(),
            ));
        }
        if next_gamma < gamma_min || next_gamma > gamma_max {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 abort corridor gamma bounds failed".to_string(),
            ));
        }
    } else {
        if stage_q_max > parameters.q_max {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 dynamic pressure exceeded q_max".to_string(),
            ));
        }
        if stage_q_dot_max > parameters.q_dot_max {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 heating rate exceeded q_dot_max".to_string(),
            ));
        }
        if next_altitude < parameters.h_min {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 altitude dropped below h_min".to_string(),
            ));
        }
        if next_velocity > parameters.v_max {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 velocity exceeded v_max".to_string(),
            ));
        }
        if abs_bigint(next_gamma.clone()) > parameters.gamma_bound {
            return Err(ZkfError::InvalidArtifact(
                "accepted RK4 flight-path angle exceeded gamma_bound".to_string(),
            ));
        }
    }

    Ok(ReentryAcceptedStepResult {
        current_altitude: altitude.clone(),
        current_downrange: downrange.clone(),
        current_velocity: velocity.clone(),
        current_gamma: gamma.clone(),
        current_heat: cumulative_heat.clone(),
        current_abort_latch: abort_latch,
        stage_q_max,
        stage_q_dot_max,
        next_altitude,
        next_downrange,
        next_velocity,
        next_gamma,
        next_heat,
        abort_triggered,
        next_abort_latch,
    })
}

fn simulate_reentry_rk4_path_from_v2(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<Vec<ReentryAcceptedStepResult>> {
    let steps = mission_pack.public_envelope.certified_horizon_steps;
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "accepted RK4 mission pack must use a nonzero certified horizon".to_string(),
        ));
    }
    if mission_pack.private.bank_angle_cosines.len() != steps {
        return Err(ZkfError::InvalidArtifact(format!(
            "accepted RK4 horizon {} did not match bank-angle schedule length {}",
            steps,
            mission_pack.private.bank_angle_cosines.len()
        )));
    }

    let parameters = accepted_public_parameters_from_envelope(&mission_pack.public_envelope)?;
    let mut altitude =
        accepted_parse_decimal_string(altitude_name(), &mission_pack.private.initial_altitude)?;
    let mut downrange = zero();
    let mut velocity =
        accepted_parse_decimal_string(velocity_name(), &mission_pack.private.initial_velocity)?;
    let mut gamma = accepted_parse_decimal_string(
        gamma_name(),
        &mission_pack.private.initial_flight_path_angle,
    )?;
    let mut cumulative_heat = zero();
    let mut abort_latch = false;
    let mut results = Vec::with_capacity(steps);

    for (step, bank_cos_value) in mission_pack.private.bank_angle_cosines.iter().enumerate() {
        let bank_cos = accepted_parse_decimal_string(&bank_cos_name(step), bank_cos_value)?;
        let result = simulate_reentry_rk4_step(
            &altitude,
            &downrange,
            &velocity,
            &gamma,
            &cumulative_heat,
            abort_latch,
            &bank_cos,
            mission_pack,
            &parameters,
        )?;
        altitude = result.next_altitude.clone();
        downrange = result.next_downrange.clone();
        velocity = result.next_velocity.clone();
        gamma = result.next_gamma.clone();
        cumulative_heat = result.next_heat.clone();
        abort_latch = result.next_abort_latch;
        results.push(result);
    }

    Ok(results)
}

pub fn build_reentry_oracle_summary_v1(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<ReentryOracleSummaryV1> {
    let steps = simulate_reentry_rk4_path_from_v2(mission_pack)?;
    let peak_dynamic_pressure = steps
        .iter()
        .map(|step| step.stage_q_max.clone())
        .max()
        .unwrap_or_else(zero);
    let peak_heating_rate = steps
        .iter()
        .map(|step| step.stage_q_dot_max.clone())
        .max()
        .unwrap_or_else(zero);
    Ok(ReentryOracleSummaryV1 {
        mission_id: mission_pack.private_model_commitments.mission_id.clone(),
        mission_pack_digest: reentry_mission_pack_v2_digest(mission_pack)?,
        oracle_lane: "deterministic-rust-rk4-oracle".to_string(),
        model_revision: "reentry-mission-pack-v2-rk4-private-table-abort".to_string(),
        horizon_steps: mission_pack.public_envelope.certified_horizon_steps,
        fixed_point_scale: accepted_scale().to_str_radix(10),
        peak_dynamic_pressure: accepted_scaled_bigint_to_decimal_string(&peak_dynamic_pressure),
        peak_heating_rate: accepted_scaled_bigint_to_decimal_string(&peak_heating_rate),
        compliance_bit: true,
    })
}

pub fn compare_reentry_receipt_to_oracle_v1(
    receipt: &ReentryAssuranceReceiptV2,
    oracle: &ReentryOracleSummaryV1,
) -> ReentryOracleComparisonV1 {
    let mut mismatches = BTreeMap::new();
    let compared = [
        (
            "peak_dynamic_pressure",
            receipt.peak_dynamic_pressure.clone(),
            oracle.peak_dynamic_pressure.clone(),
        ),
        (
            "peak_heating_rate",
            receipt.peak_heating_rate.clone(),
            oracle.peak_heating_rate.clone(),
        ),
        (
            "compliance_bit",
            receipt.compliance_bit.to_string(),
            oracle.compliance_bit.to_string(),
        ),
        (
            "horizon_steps",
            receipt.horizon_steps.to_string(),
            oracle.horizon_steps.to_string(),
        ),
    ];
    for (field, theorem_value, oracle_value) in compared {
        if theorem_value != oracle_value {
            mismatches.insert(
                field.to_string(),
                format!("theorem={theorem_value} oracle={oracle_value}"),
            );
        }
    }
    ReentryOracleComparisonV1 {
        mission_id: receipt.mission_id.clone(),
        mission_pack_digest: receipt.mission_pack_digest.clone(),
        theorem_lane: receipt.theorem_lane.clone(),
        oracle_lane: oracle.oracle_lane.clone(),
        tolerance_policy: "exact-equality".to_string(),
        compared_fields: vec![
            "peak_dynamic_pressure".to_string(),
            "peak_heating_rate".to_string(),
            "compliance_bit".to_string(),
            "horizon_steps".to_string(),
        ],
        matched: mismatches.is_empty(),
        mismatches,
    }
}

#[derive(Debug, Clone)]
struct AcceptedInterpolationSelection {
    row_index: usize,
    input_start: BigInt,
    input_end: BigInt,
    value_start: BigInt,
    value_end: BigInt,
    span: BigInt,
    offset: BigInt,
    upper_slack: BigInt,
    delta: BigInt,
    quotient: BigInt,
    remainder: BigInt,
    slack: BigInt,
    interpolated: BigInt,
}

#[derive(Debug, Clone)]
struct AcceptedAbortSelection {
    row_index: usize,
    altitude_start: BigInt,
    altitude_end: BigInt,
    lower_slack: BigInt,
    upper_slack: BigInt,
    velocity_min: BigInt,
    velocity_max: BigInt,
    gamma_min: BigInt,
    gamma_max: BigInt,
}

#[derive(Debug, Clone)]
struct AcceptedStageEvaluation {
    altitude: BigInt,
    downrange: BigInt,
    velocity: BigInt,
    gamma: BigInt,
    heat: BigInt,
    atmosphere: AcceptedInterpolationSelection,
    sine: AcceptedInterpolationSelection,
    abort_selection: AcceptedAbortSelection,
    cos_gamma: BigInt,
    cos_remainder: BigInt,
    cos_upper_slack: BigInt,
    v_sq: BigInt,
    v_sq_fp: BigInt,
    v_sq_fp_remainder: BigInt,
    v_sq_fp_slack: BigInt,
    v_cubed_fp: BigInt,
    v_cubed_remainder: BigInt,
    v_cubed_slack: BigInt,
    rho_v_sq: BigInt,
    rho_v_sq_remainder: BigInt,
    rho_v_sq_slack: BigInt,
    q_i: BigInt,
    q_i_remainder: BigInt,
    q_i_slack: BigInt,
    drag_force: BigInt,
    drag_remainder: BigInt,
    drag_slack: BigInt,
    lift_cos: BigInt,
    lift_cos_remainder: BigInt,
    lift_cos_slack: BigInt,
    lift_force: BigInt,
    lift_remainder: BigInt,
    lift_slack: BigInt,
    drag_accel: BigInt,
    drag_accel_remainder: BigInt,
    drag_accel_slack: BigInt,
    lift_accel: BigInt,
    lift_accel_remainder: BigInt,
    lift_accel_slack: BigInt,
    g_sin_gamma: BigInt,
    g_sin_gamma_remainder: BigInt,
    g_sin_gamma_slack: BigInt,
    dv_accel: BigInt,
    dv: BigInt,
    dv_remainder: BigInt,
    dv_slack: BigInt,
    v_sin: BigInt,
    v_cos: BigInt,
    dh: BigInt,
    dh_remainder: BigInt,
    dh_slack: BigInt,
    dx: BigInt,
    dx_remainder: BigInt,
    dx_slack: BigInt,
    lift_over_v: BigInt,
    lift_over_v_remainder: BigInt,
    lift_over_v_slack: BigInt,
    g_cos_gamma: BigInt,
    g_cos_gamma_remainder: BigInt,
    g_cos_gamma_slack: BigInt,
    gcos_over_v: BigInt,
    gcos_over_v_remainder: BigInt,
    gcos_over_v_slack: BigInt,
    dgamma_accel: BigInt,
    dgamma: BigInt,
    dgamma_remainder: BigInt,
    dgamma_slack: BigInt,
    rho_over_rn_fp: BigInt,
    rho_over_rn_remainder: BigInt,
    rho_over_rn_slack: BigInt,
    sqrt_rho_over_rn_fp: BigInt,
    sqrt_rho_over_rn_remainder: BigInt,
    sqrt_rho_over_rn_upper_slack: BigInt,
    heating_factor: BigInt,
    heating_factor_remainder: BigInt,
    heating_factor_slack: BigInt,
    q_dot_i: BigInt,
    q_dot_remainder: BigInt,
    q_dot_slack: BigInt,
}

#[derive(Debug, Clone)]
struct AcceptedStepEvaluation {
    stages: [AcceptedStageEvaluation; 4],
    weighted_dh: BigInt,
    weighted_dh_remainder: BigInt,
    weighted_dh_slack: BigInt,
    weighted_dx: BigInt,
    weighted_dx_remainder: BigInt,
    weighted_dx_slack: BigInt,
    weighted_dv: BigInt,
    weighted_dv_remainder: BigInt,
    weighted_dv_slack: BigInt,
    weighted_dgamma: BigInt,
    weighted_dgamma_remainder: BigInt,
    weighted_dgamma_slack: BigInt,
    weighted_dheat: BigInt,
    weighted_dheat_remainder: BigInt,
    weighted_dheat_slack: BigInt,
    next_altitude: BigInt,
    next_downrange: BigInt,
    next_velocity: BigInt,
    next_gamma: BigInt,
    next_heat: BigInt,
    q_abort_predicate: bool,
    q_dot_abort_predicate: bool,
    altitude_abort_predicate: bool,
    velocity_abort_predicate: bool,
    trigger: bool,
    first_trigger: bool,
    next_abort_latch: bool,
    nominal_ok: bool,
    abort_ok: bool,
    step_valid: bool,
}

fn accepted_interpolation_from_atmosphere_bands(
    altitude: &BigInt,
    bands: &[ReentryAtmosphereBandRowV1],
) -> ZkfResult<AcceptedInterpolationSelection> {
    for (row_index, band) in bands.iter().enumerate() {
        let input_start =
            accepted_parse_decimal_string("atmosphere.altitude_start", &band.altitude_start)?;
        let input_end =
            accepted_parse_decimal_string("atmosphere.altitude_end", &band.altitude_end)?;
        if altitude < &input_start || altitude > &input_end {
            continue;
        }
        let value_start =
            accepted_parse_decimal_string("atmosphere.density_start", &band.density_start)?;
        let value_end = accepted_parse_decimal_string("atmosphere.density_end", &band.density_end)?;
        let span = &input_end - &input_start;
        let offset = altitude - &input_start;
        let upper_slack = &input_end - altitude;
        let delta = &value_end - &value_start;
        let (quotient, remainder, slack) = euclidean_division(&(&offset * &delta), &span)?;
        let interpolated = &value_start + &quotient;
        return Ok(AcceptedInterpolationSelection {
            row_index,
            input_start,
            input_end,
            value_start,
            value_end,
            span,
            offset,
            upper_slack,
            delta,
            quotient,
            remainder,
            slack,
            interpolated,
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted reentry altitude {} is outside the private atmosphere table",
        accepted_scaled_bigint_to_decimal_string(altitude)
    )))
}

fn accepted_interpolation_from_sine_bands(
    gamma: &BigInt,
    bands: &[ReentrySineBandRowV1],
) -> ZkfResult<AcceptedInterpolationSelection> {
    for (row_index, band) in bands.iter().enumerate() {
        let input_start = accepted_parse_decimal_string("sine.gamma_start", &band.gamma_start)?;
        let input_end = accepted_parse_decimal_string("sine.gamma_end", &band.gamma_end)?;
        if gamma < &input_start || gamma > &input_end {
            continue;
        }
        let value_start = accepted_parse_decimal_string("sine.sine_start", &band.sine_start)?;
        let value_end = accepted_parse_decimal_string("sine.sine_end", &band.sine_end)?;
        let span = &input_end - &input_start;
        let offset = gamma - &input_start;
        let upper_slack = &input_end - gamma;
        let delta = &value_end - &value_start;
        let (quotient, remainder, slack) = euclidean_division(&(&offset * &delta), &span)?;
        let interpolated = &value_start + &quotient;
        return Ok(AcceptedInterpolationSelection {
            row_index,
            input_start,
            input_end,
            value_start,
            value_end,
            span,
            offset,
            upper_slack,
            delta,
            quotient,
            remainder,
            slack,
            interpolated,
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted reentry flight-path angle {} is outside the private sine table",
        accepted_scaled_bigint_to_decimal_string(gamma)
    )))
}

fn accepted_abort_selection(
    altitude: &BigInt,
    bands: &[ReentryAbortCorridorBandRowV1],
) -> ZkfResult<AcceptedAbortSelection> {
    for (row_index, band) in bands.iter().enumerate() {
        let altitude_start =
            accepted_parse_decimal_string("abort_corridor.altitude_start", &band.altitude_start)?;
        let altitude_end =
            accepted_parse_decimal_string("abort_corridor.altitude_end", &band.altitude_end)?;
        if altitude < &altitude_start || altitude > &altitude_end {
            continue;
        }
        return Ok(AcceptedAbortSelection {
            row_index,
            altitude_start: altitude_start.clone(),
            altitude_end: altitude_end.clone(),
            lower_slack: altitude - &altitude_start,
            upper_slack: &altitude_end - altitude,
            velocity_min: accepted_parse_decimal_string(
                "abort_corridor.velocity_min",
                &band.velocity_min,
            )?,
            velocity_max: accepted_parse_decimal_string(
                "abort_corridor.velocity_max",
                &band.velocity_max,
            )?,
            gamma_min: accepted_parse_decimal_string("abort_corridor.gamma_min", &band.gamma_min)?,
            gamma_max: accepted_parse_decimal_string("abort_corridor.gamma_max", &band.gamma_max)?,
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "accepted reentry abort corridor did not cover altitude {}",
        accepted_scaled_bigint_to_decimal_string(altitude)
    )))
}

#[allow(clippy::too_many_arguments)]
fn accepted_stage_evaluation(
    altitude: &BigInt,
    downrange: &BigInt,
    velocity: &BigInt,
    gamma: &BigInt,
    heat: &BigInt,
    bank_cos: &BigInt,
    mission_pack: &ReentryMissionPackV2,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<AcceptedStageEvaluation> {
    let scale = accepted_scale();
    let scale_sq = accepted_scale_squared();
    let atmosphere = accepted_interpolation_from_atmosphere_bands(
        altitude,
        &mission_pack.private.atmosphere_bands,
    )?;
    let sine = accepted_interpolation_from_sine_bands(gamma, &mission_pack.private.sine_bands)?;
    let abort_selection =
        accepted_abort_selection(altitude, &mission_pack.private.abort_corridor_bands)?;
    let rho = atmosphere.interpolated.clone();
    let sin_gamma = sine.interpolated.clone();
    let cos_target = &scale_sq - (&sin_gamma * &sin_gamma);
    if cos_target < zero() {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry cosine support underflowed".to_string(),
        ));
    }
    let (cos_gamma, cos_remainder, cos_upper_slack) = floor_sqrt_support(&cos_target)?;

    let mass =
        accepted_parse_decimal_string(mass_input_name(), &mission_pack.private.vehicle_mass)?;
    let s_ref = accepted_parse_decimal_string(sref_name(), &mission_pack.private.reference_area)?;
    let c_d = accepted_parse_decimal_string(cd_name(), &mission_pack.private.drag_coefficient)?;
    let c_l = accepted_parse_decimal_string(cl_name(), &mission_pack.private.lift_coefficient)?;
    let r_n = accepted_parse_decimal_string(rn_name(), &mission_pack.private.nose_radius)?;

    let v_sq = velocity * velocity;
    let (v_sq_fp, v_sq_fp_remainder, v_sq_fp_slack) = euclidean_division(&v_sq, &scale)?;
    let (v_cubed_fp, v_cubed_remainder, v_cubed_slack) =
        euclidean_division(&(&v_sq_fp * velocity), &scale)?;
    let (rho_v_sq, rho_v_sq_remainder, rho_v_sq_slack) =
        euclidean_division(&(rho.clone() * &v_sq), &scale)?;
    let (q_i, q_i_remainder, q_i_slack) = euclidean_division(&rho_v_sq, &(two() * &scale))?;
    let (drag_force, drag_remainder, drag_slack) =
        euclidean_division(&(&q_i * &s_ref * &c_d), &scale_sq)?;
    let (lift_cos, lift_cos_remainder, lift_cos_slack) =
        euclidean_division(&(&c_l * bank_cos), &scale)?;
    let (lift_force, lift_remainder, lift_slack) =
        euclidean_division(&(&q_i * &s_ref * &lift_cos), &scale_sq)?;
    let (drag_accel, drag_accel_remainder, drag_accel_slack) =
        euclidean_division(&(&drag_force * &scale), &mass)?;
    let (lift_accel, lift_accel_remainder, lift_accel_slack) =
        euclidean_division(&(&lift_force * &scale), &mass)?;
    let (g_sin_gamma, g_sin_gamma_remainder, g_sin_gamma_slack) =
        euclidean_division(&(&parameters.g_0 * &sin_gamma), &scale)?;
    let dv_accel = -&drag_accel - &g_sin_gamma;
    let (dv, dv_remainder, dv_slack) = euclidean_division(&dv_accel, &one())?;
    let v_sin = velocity * &sin_gamma;
    let (dh, dh_remainder, dh_slack) = euclidean_division(&v_sin, &scale)?;
    let v_cos = velocity * &cos_gamma;
    let (dx, dx_remainder, dx_slack) = euclidean_division(&v_cos, &scale)?;
    let (lift_over_v, lift_over_v_remainder, lift_over_v_slack) =
        euclidean_division(&(&lift_accel * &scale), velocity)?;
    let (g_cos_gamma, g_cos_gamma_remainder, g_cos_gamma_slack) =
        euclidean_division(&(&parameters.g_0 * &cos_gamma), &scale)?;
    let (gcos_over_v, gcos_over_v_remainder, gcos_over_v_slack) =
        euclidean_division(&(&g_cos_gamma * &scale), velocity)?;
    let dgamma_accel = &lift_over_v - &gcos_over_v;
    let (dgamma, dgamma_remainder, dgamma_slack) = euclidean_division(&dgamma_accel, &one())?;
    let (rho_over_rn_fp, rho_over_rn_remainder, rho_over_rn_slack) =
        euclidean_division(&(rho.clone() * &scale), &r_n)?;
    let (sqrt_rho_over_rn_fp, sqrt_rho_over_rn_remainder, sqrt_rho_over_rn_upper_slack) =
        floor_sqrt_support(&(&rho_over_rn_fp * &scale))?;
    let (heating_factor, heating_factor_remainder, heating_factor_slack) =
        euclidean_division(&(&parameters.k_sg * &sqrt_rho_over_rn_fp), &scale)?;
    let (q_dot_i, q_dot_remainder, q_dot_slack) =
        euclidean_division(&(&heating_factor * &v_cubed_fp), &scale)?;

    Ok(AcceptedStageEvaluation {
        altitude: altitude.clone(),
        downrange: downrange.clone(),
        velocity: velocity.clone(),
        gamma: gamma.clone(),
        heat: heat.clone(),
        atmosphere,
        sine,
        abort_selection,
        cos_gamma,
        cos_remainder,
        cos_upper_slack,
        v_sq,
        v_sq_fp,
        v_sq_fp_remainder,
        v_sq_fp_slack,
        v_cubed_fp,
        v_cubed_remainder,
        v_cubed_slack,
        rho_v_sq,
        rho_v_sq_remainder,
        rho_v_sq_slack,
        q_i,
        q_i_remainder,
        q_i_slack,
        drag_force,
        drag_remainder,
        drag_slack,
        lift_cos,
        lift_cos_remainder,
        lift_cos_slack,
        lift_force,
        lift_remainder,
        lift_slack,
        drag_accel,
        drag_accel_remainder,
        drag_accel_slack,
        lift_accel,
        lift_accel_remainder,
        lift_accel_slack,
        g_sin_gamma,
        g_sin_gamma_remainder,
        g_sin_gamma_slack,
        dv_accel,
        dv,
        dv_remainder,
        dv_slack,
        v_sin,
        v_cos,
        dh,
        dh_remainder,
        dh_slack,
        dx,
        dx_remainder,
        dx_slack,
        lift_over_v,
        lift_over_v_remainder,
        lift_over_v_slack,
        g_cos_gamma,
        g_cos_gamma_remainder,
        g_cos_gamma_slack,
        gcos_over_v,
        gcos_over_v_remainder,
        gcos_over_v_slack,
        dgamma_accel,
        dgamma,
        dgamma_remainder,
        dgamma_slack,
        rho_over_rn_fp,
        rho_over_rn_remainder,
        rho_over_rn_slack,
        sqrt_rho_over_rn_fp,
        sqrt_rho_over_rn_remainder,
        sqrt_rho_over_rn_upper_slack,
        heating_factor,
        heating_factor_remainder,
        heating_factor_slack,
        q_dot_i,
        q_dot_remainder,
        q_dot_slack,
    })
}

fn accepted_weighted_delta(
    k1: &BigInt,
    k2: &BigInt,
    k3: &BigInt,
    k4: &BigInt,
) -> ZkfResult<(BigInt, BigInt, BigInt)> {
    euclidean_division(
        &(k1 + (BigInt::from(2u8) * k2) + (BigInt::from(2u8) * k3) + k4),
        &BigInt::from(6u8),
    )
}

fn accepted_stage_nominal_ok(
    stage: &AcceptedStageEvaluation,
    parameters: &ReentryPublicParameters,
) -> bool {
    stage.q_i <= parameters.q_max
        && stage.q_dot_i <= parameters.q_dot_max
        && stage.altitude >= parameters.h_min
        && stage.velocity <= parameters.v_max
        && abs_bigint(stage.gamma.clone()) <= parameters.gamma_bound
}

fn accepted_stage_abort_ok(stage: &AcceptedStageEvaluation) -> bool {
    stage.velocity >= stage.abort_selection.velocity_min
        && stage.velocity <= stage.abort_selection.velocity_max
        && stage.gamma >= stage.abort_selection.gamma_min
        && stage.gamma <= stage.abort_selection.gamma_max
}

fn accepted_step_evaluation(
    altitude: &BigInt,
    downrange: &BigInt,
    velocity: &BigInt,
    gamma: &BigInt,
    heat: &BigInt,
    current_abort_latch: bool,
    bank_cos: &BigInt,
    mission_pack: &ReentryMissionPackV2,
    parameters: &ReentryPublicParameters,
) -> ZkfResult<AcceptedStepEvaluation> {
    let k1 = accepted_stage_evaluation(
        altitude,
        downrange,
        velocity,
        gamma,
        heat,
        bank_cos,
        mission_pack,
        parameters,
    )?;
    let h2 = altitude + accepted_half_step(&k1.dh)?;
    let x2 = downrange + accepted_half_step(&k1.dx)?;
    let v2 = velocity + accepted_half_step(&k1.dv)?;
    let g2 = gamma + accepted_half_step(&k1.dgamma)?;
    let heat2 = heat + accepted_half_step(&k1.q_dot_i)?;
    let k2 = accepted_stage_evaluation(
        &h2,
        &x2,
        &v2,
        &g2,
        &heat2,
        bank_cos,
        mission_pack,
        parameters,
    )?;
    let h3 = altitude + accepted_half_step(&k2.dh)?;
    let x3 = downrange + accepted_half_step(&k2.dx)?;
    let v3 = velocity + accepted_half_step(&k2.dv)?;
    let g3 = gamma + accepted_half_step(&k2.dgamma)?;
    let heat3 = heat + accepted_half_step(&k2.q_dot_i)?;
    let k3 = accepted_stage_evaluation(
        &h3,
        &x3,
        &v3,
        &g3,
        &heat3,
        bank_cos,
        mission_pack,
        parameters,
    )?;
    let h4 = altitude + &k3.dh;
    let x4 = downrange + &k3.dx;
    let v4 = velocity + &k3.dv;
    let g4 = gamma + &k3.dgamma;
    let heat4 = heat + &k3.q_dot_i;
    let k4 = accepted_stage_evaluation(
        &h4,
        &x4,
        &v4,
        &g4,
        &heat4,
        bank_cos,
        mission_pack,
        parameters,
    )?;

    let (weighted_dh, weighted_dh_remainder, weighted_dh_slack) =
        accepted_weighted_delta(&k1.dh, &k2.dh, &k3.dh, &k4.dh)?;
    let (weighted_dx, weighted_dx_remainder, weighted_dx_slack) =
        accepted_weighted_delta(&k1.dx, &k2.dx, &k3.dx, &k4.dx)?;
    let (weighted_dv, weighted_dv_remainder, weighted_dv_slack) =
        accepted_weighted_delta(&k1.dv, &k2.dv, &k3.dv, &k4.dv)?;
    let (weighted_dgamma, weighted_dgamma_remainder, weighted_dgamma_slack) =
        accepted_weighted_delta(&k1.dgamma, &k2.dgamma, &k3.dgamma, &k4.dgamma)?;
    let (weighted_dheat, weighted_dheat_remainder, weighted_dheat_slack) =
        accepted_weighted_delta(&k1.q_dot_i, &k2.q_dot_i, &k3.q_dot_i, &k4.q_dot_i)?;

    let next_altitude = altitude + &weighted_dh;
    let next_downrange = downrange + &weighted_dx;
    let next_velocity = velocity + &weighted_dv;
    let next_gamma = gamma + &weighted_dgamma;
    let next_heat = heat + &weighted_dheat;

    let abort_q_trigger = accepted_parse_decimal_string(
        accepted_abort_q_trigger_name(),
        &mission_pack.private.abort_thresholds.q_trigger_min,
    )?;
    let abort_q_dot_trigger = accepted_parse_decimal_string(
        accepted_abort_q_dot_trigger_name(),
        &mission_pack.private.abort_thresholds.q_dot_trigger_min,
    )?;
    let abort_altitude_floor = accepted_parse_decimal_string(
        accepted_abort_altitude_floor_name(),
        &mission_pack.private.abort_thresholds.altitude_floor,
    )?;
    let abort_velocity_ceiling = accepted_parse_decimal_string(
        accepted_abort_velocity_ceiling_name(),
        &mission_pack.private.abort_thresholds.velocity_ceiling,
    )?;

    let q_abort_predicate = [&k1, &k2, &k3, &k4]
        .iter()
        .any(|stage| stage.q_i >= abort_q_trigger);
    let q_dot_abort_predicate = [&k1, &k2, &k3, &k4]
        .iter()
        .any(|stage| stage.q_dot_i >= abort_q_dot_trigger);
    let altitude_abort_predicate = next_altitude <= abort_altitude_floor;
    let velocity_abort_predicate = next_velocity >= abort_velocity_ceiling;
    let trigger = q_abort_predicate
        || q_dot_abort_predicate
        || altitude_abort_predicate
        || velocity_abort_predicate;
    let first_trigger = trigger && !current_abort_latch;
    let next_abort_latch = current_abort_latch || trigger;

    let nominal_ok = accepted_stage_nominal_ok(&k1, parameters)
        && accepted_stage_nominal_ok(&k2, parameters)
        && accepted_stage_nominal_ok(&k3, parameters)
        && accepted_stage_nominal_ok(&k4, parameters);
    let abort_ok = accepted_stage_abort_ok(&k1)
        && accepted_stage_abort_ok(&k2)
        && accepted_stage_abort_ok(&k3)
        && accepted_stage_abort_ok(&k4);
    let step_valid = if current_abort_latch {
        abort_ok
    } else {
        nominal_ok || trigger
    };
    if !step_valid {
        return Err(ZkfError::InvalidArtifact(
            "accepted reentry RK4 step failed nominal-or-valid-abort constraints".to_string(),
        ));
    }

    Ok(AcceptedStepEvaluation {
        stages: [k1, k2, k3, k4],
        weighted_dh,
        weighted_dh_remainder,
        weighted_dh_slack,
        weighted_dx,
        weighted_dx_remainder,
        weighted_dx_slack,
        weighted_dv,
        weighted_dv_remainder,
        weighted_dv_slack,
        weighted_dgamma,
        weighted_dgamma_remainder,
        weighted_dgamma_slack,
        weighted_dheat,
        weighted_dheat_remainder,
        weighted_dheat_slack,
        next_altitude,
        next_downrange,
        next_velocity,
        next_gamma,
        next_heat,
        q_abort_predicate,
        q_dot_abort_predicate,
        altitude_abort_predicate,
        velocity_abort_predicate,
        trigger,
        first_trigger,
        next_abort_latch,
        nominal_ok,
        abort_ok,
        step_valid,
    })
}

fn append_accepted_stage_constraints(
    builder: &mut ProgramBuilder,
    shape: &AcceptedReentryShape,
    step: usize,
    stage: usize,
) -> ZkfResult<()> {
    let stage_h = accepted_stage_altitude_name(step, stage);
    let stage_x = accepted_stage_downrange_name(step, stage);
    let stage_v = accepted_stage_velocity_name(step, stage);
    let stage_gamma = accepted_stage_gamma_name(step, stage);
    let stage_heat = accepted_stage_heat_name(step, stage);

    append_nonnegative_bound(
        builder,
        &stage_h,
        &accepted_altitude_bound(),
        &format!("{}_h_bound", accepted_stage_prefix(step, stage)),
    )?;
    append_nonnegative_bound(
        builder,
        &stage_x,
        &accepted_downrange_bound(),
        &format!("{}_x_bound", accepted_stage_prefix(step, stage)),
    )?;
    append_nonnegative_bound(
        builder,
        &stage_v,
        &accepted_velocity_bound(),
        &format!("{}_v_bound", accepted_stage_prefix(step, stage)),
    )?;
    append_nonzero_constraint(
        builder,
        &stage_v,
        &format!("{}_v_nonzero", accepted_stage_prefix(step, stage)),
    )?;
    append_signed_bound(
        builder,
        &stage_gamma,
        &accepted_gamma_bound(),
        &format!("{}_gamma_bound", accepted_stage_prefix(step, stage)),
    )?;
    append_nonnegative_bound(
        builder,
        &stage_heat,
        &accepted_heat_bound(),
        &format!("{}_heat_bound", accepted_stage_prefix(step, stage)),
    )?;

    let atmosphere_rows = (0..shape.atmosphere_rows)
        .map(accepted_atmosphere_row_input_names)
        .collect::<Vec<_>>();
    let sine_rows = (0..shape.sine_rows)
        .map(accepted_sine_row_input_names)
        .collect::<Vec<_>>();
    let abort_rows = (0..shape.abort_rows)
        .map(accepted_abort_row_input_names)
        .collect::<Vec<_>>();

    let atmosphere_selectors = (0..shape.atmosphere_rows)
        .map(|row| accepted_stage_atmosphere_selector_name(step, stage, row))
        .collect::<Vec<_>>();
    let atmosphere_selected_fields = vec![
        accepted_stage_selected_atmosphere_start_name(step, stage),
        accepted_stage_selected_atmosphere_end_name(step, stage),
        accepted_stage_selected_density_start_name(step, stage),
        accepted_stage_selected_density_end_name(step, stage),
    ];
    append_one_hot_row_selection(
        builder,
        &accepted_stage_name(step, stage, "atmosphere"),
        &atmosphere_rows,
        &atmosphere_selected_fields,
        &atmosphere_selectors,
    )?;
    append_piecewise_interpolation_constraints(
        builder,
        &accepted_stage_name(step, stage, "atmosphere_interp"),
        &stage_h,
        &atmosphere_selected_fields[0],
        &atmosphere_selected_fields[1],
        &atmosphere_selected_fields[2],
        &atmosphere_selected_fields[3],
        &accepted_stage_rho_name(step, stage),
        &accepted_altitude_bound(),
        &accepted_density_bound(),
        true,
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_rho_name(step, stage),
        &accepted_density_bound(),
        &accepted_stage_name(step, stage, "rho"),
    )?;

    let sine_selectors = (0..shape.sine_rows)
        .map(|row| accepted_stage_sine_selector_name(step, stage, row))
        .collect::<Vec<_>>();
    let sine_selected_fields = vec![
        accepted_stage_selected_sine_start_name(step, stage),
        accepted_stage_selected_sine_end_name(step, stage),
        accepted_stage_selected_sine_value_start_name(step, stage),
        accepted_stage_selected_sine_value_end_name(step, stage),
    ];
    append_one_hot_row_selection(
        builder,
        &accepted_stage_name(step, stage, "sine"),
        &sine_rows,
        &sine_selected_fields,
        &sine_selectors,
    )?;
    append_piecewise_interpolation_constraints(
        builder,
        &accepted_stage_name(step, stage, "sine_interp"),
        &stage_gamma,
        &sine_selected_fields[0],
        &sine_selected_fields[1],
        &sine_selected_fields[2],
        &sine_selected_fields[3],
        &accepted_stage_sin_gamma_name(step, stage),
        &accepted_gamma_bound(),
        &accepted_trig_bound(),
        true,
    )?;

    let abort_selectors = (0..shape.abort_rows)
        .map(|row| accepted_stage_abort_selector_name(step, stage, row))
        .collect::<Vec<_>>();
    let abort_selected_fields = vec![
        accepted_stage_selected_abort_altitude_start_name(step, stage),
        accepted_stage_selected_abort_altitude_end_name(step, stage),
        accepted_stage_selected_abort_velocity_min_name(step, stage),
        accepted_stage_selected_abort_velocity_max_name(step, stage),
        accepted_stage_selected_abort_gamma_min_name(step, stage),
        accepted_stage_selected_abort_gamma_max_name(step, stage),
    ];
    append_one_hot_row_selection(
        builder,
        &accepted_stage_name(step, stage, "abort"),
        &abort_rows,
        &abort_selected_fields,
        &abort_selectors,
    )?;
    let abort_lower_slack = accepted_stage_name(step, stage, "abort_lower_slack");
    builder.private_signal(&abort_lower_slack)?;
    builder.constrain_equal(
        signal_expr(&abort_lower_slack),
        sub_expr(
            signal_expr(&stage_h),
            signal_expr(&abort_selected_fields[0]),
        ),
    )?;
    append_nonnegative_bound(
        builder,
        &abort_lower_slack,
        &accepted_altitude_bound(),
        &format!("{}_abort_lower", accepted_stage_prefix(step, stage)),
    )?;
    let abort_upper_slack = accepted_stage_name(step, stage, "abort_upper_slack");
    builder.private_signal(&abort_upper_slack)?;
    builder.constrain_equal(
        signal_expr(&abort_upper_slack),
        sub_expr(
            signal_expr(&abort_selected_fields[1]),
            signal_expr(&stage_h),
        ),
    )?;
    append_nonnegative_bound(
        builder,
        &abort_upper_slack,
        &accepted_altitude_bound(),
        &format!("{}_abort_upper", accepted_stage_prefix(step, stage)),
    )?;

    append_floor_sqrt_constraints(
        builder,
        sub_expr(
            const_expr(&accepted_scale_squared()),
            mul_expr(
                signal_expr(&accepted_stage_sin_gamma_name(step, stage)),
                signal_expr(&accepted_stage_sin_gamma_name(step, stage)),
            ),
        ),
        &accepted_stage_cos_gamma_name(step, stage),
        &accepted_stage_cos_remainder_name(step, stage),
        &accepted_stage_cos_upper_slack_name(step, stage),
        &accepted_trig_bound(),
        &sqrt_support_bound(&accepted_trig_bound()),
        &accepted_stage_name(step, stage, "cos"),
    )?;

    let v_sq = accepted_stage_name(step, stage, "v_sq");
    builder.private_signal(&v_sq)?;
    builder.constrain_equal(
        signal_expr(&v_sq),
        mul_expr(signal_expr(&stage_v), signal_expr(&stage_v)),
    )?;
    append_nonnegative_bound(
        builder,
        &v_sq,
        &accepted_v_sq_bound(),
        &accepted_stage_name(step, stage, "v_sq"),
    )?;

    append_exact_division_constraints(
        builder,
        signal_expr(&v_sq),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "v_sq_fp"),
        &accepted_stage_name(step, stage, "v_sq_fp_remainder"),
        &accepted_stage_name(step, stage, "v_sq_fp_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "v_sq_fp"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_name(step, stage, "v_sq_fp"),
        &accepted_v_sq_fp_bound(),
        &accepted_stage_name(step, stage, "v_sq_fp_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "v_sq_fp")),
            signal_expr(&stage_v),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "v_cubed_fp"),
        &accepted_stage_name(step, stage, "v_cubed_fp_remainder"),
        &accepted_stage_name(step, stage, "v_cubed_fp_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "v_cubed_fp"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_name(step, stage, "v_cubed_fp"),
        &accepted_v_cubed_fp_bound(),
        &accepted_stage_name(step, stage, "v_cubed_fp_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_rho_name(step, stage)),
            signal_expr(&v_sq),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "rho_v_sq"),
        &accepted_stage_name(step, stage, "rho_v_sq_remainder"),
        &accepted_stage_name(step, stage, "rho_v_sq_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "rho_v_sq"),
    )?;

    append_exact_division_constraints(
        builder,
        signal_expr(&accepted_stage_name(step, stage, "rho_v_sq")),
        const_expr(&(two() * accepted_scale())),
        &accepted_stage_q_name(step, stage),
        &accepted_stage_name(step, stage, "q_remainder"),
        &accepted_stage_name(step, stage, "q_slack"),
        &(two() * accepted_scale()),
        &accepted_stage_name(step, stage, "q"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_q_name(step, stage),
        &accepted_dynamic_pressure_bound(),
        &accepted_stage_name(step, stage, "q_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_q_name(step, stage)),
            mul_expr(signal_expr(sref_name()), signal_expr(cd_name())),
        ),
        const_expr(&accepted_scale_squared()),
        &accepted_stage_name(step, stage, "drag"),
        &accepted_stage_name(step, stage, "drag_remainder"),
        &accepted_stage_name(step, stage, "drag_slack"),
        &accepted_scale_squared(),
        &accepted_stage_name(step, stage, "drag"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(signal_expr(cl_name()), signal_expr(&bank_cos_name(step))),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "lift_cos"),
        &accepted_stage_name(step, stage, "lift_cos_remainder"),
        &accepted_stage_name(step, stage, "lift_cos_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "lift_cos"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_q_name(step, stage)),
            mul_expr(
                signal_expr(sref_name()),
                signal_expr(&accepted_stage_name(step, stage, "lift_cos")),
            ),
        ),
        const_expr(&accepted_scale_squared()),
        &accepted_stage_name(step, stage, "lift"),
        &accepted_stage_name(step, stage, "lift_remainder"),
        &accepted_stage_name(step, stage, "lift_slack"),
        &accepted_scale_squared(),
        &accepted_stage_name(step, stage, "lift"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "drag")),
            const_expr(&accepted_scale()),
        ),
        signal_expr(mass_input_name()),
        &accepted_stage_name(step, stage, "drag_accel"),
        &accepted_stage_name(step, stage, "drag_accel_remainder"),
        &accepted_stage_name(step, stage, "drag_accel_slack"),
        &accepted_mass_bound(),
        &accepted_stage_name(step, stage, "drag_accel"),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_name(step, stage, "drag_accel"),
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "drag_accel_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "lift")),
            const_expr(&accepted_scale()),
        ),
        signal_expr(mass_input_name()),
        &accepted_stage_name(step, stage, "lift_accel"),
        &accepted_stage_name(step, stage, "lift_accel_remainder"),
        &accepted_stage_name(step, stage, "lift_accel_slack"),
        &accepted_mass_bound(),
        &accepted_stage_name(step, stage, "lift_accel"),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_name(step, stage, "lift_accel"),
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "lift_accel_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(gravity_name()),
            signal_expr(&accepted_stage_sin_gamma_name(step, stage)),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "g_sin_gamma"),
        &accepted_stage_name(step, stage, "g_sin_gamma_remainder"),
        &accepted_stage_name(step, stage, "g_sin_gamma_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "g_sin_gamma"),
    )?;

    let dv_accel = accepted_stage_name(step, stage, "dv_accel");
    builder.private_signal(&dv_accel)?;
    builder.constrain_equal(
        signal_expr(&dv_accel),
        sub_expr(
            const_expr(&zero()),
            add_expr(vec![
                signal_expr(&accepted_stage_name(step, stage, "drag_accel")),
                signal_expr(&accepted_stage_name(step, stage, "g_sin_gamma")),
            ]),
        ),
    )?;
    append_signed_bound(
        builder,
        &dv_accel,
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "dv_accel_bound"),
    )?;

    builder.private_signal(&accepted_stage_dv_name(step, stage))?;
    builder.constrain_equal(
        signal_expr(&accepted_stage_dv_name(step, stage)),
        signal_expr(&dv_accel),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_dv_name(step, stage),
        &accepted_velocity_delta_bound(),
        &accepted_stage_name(step, stage, "dv_bound"),
    )?;

    let v_sin = accepted_stage_name(step, stage, "v_sin");
    builder.private_signal(&v_sin)?;
    builder.constrain_equal(
        signal_expr(&v_sin),
        mul_expr(
            signal_expr(&stage_v),
            signal_expr(&accepted_stage_sin_gamma_name(step, stage)),
        ),
    )?;
    append_exact_division_constraints(
        builder,
        signal_expr(&v_sin),
        const_expr(&accepted_scale()),
        &accepted_stage_dh_name(step, stage),
        &accepted_stage_name(step, stage, "dh_remainder"),
        &accepted_stage_name(step, stage, "dh_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "dh"),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_dh_name(step, stage),
        &accepted_altitude_delta_bound(),
        &accepted_stage_name(step, stage, "dh_bound"),
    )?;

    let v_cos = accepted_stage_name(step, stage, "v_cos");
    builder.private_signal(&v_cos)?;
    builder.constrain_equal(
        signal_expr(&v_cos),
        mul_expr(
            signal_expr(&stage_v),
            signal_expr(&accepted_stage_cos_gamma_name(step, stage)),
        ),
    )?;
    append_exact_division_constraints(
        builder,
        signal_expr(&v_cos),
        const_expr(&accepted_scale()),
        &accepted_stage_dx_name(step, stage),
        &accepted_stage_name(step, stage, "dx_remainder"),
        &accepted_stage_name(step, stage, "dx_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "dx"),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_dx_name(step, stage),
        &accepted_downrange_delta_bound(),
        &accepted_stage_name(step, stage, "dx_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "lift_accel")),
            const_expr(&accepted_scale()),
        ),
        signal_expr(&stage_v),
        &accepted_stage_name(step, stage, "lift_over_v"),
        &accepted_stage_name(step, stage, "lift_over_v_remainder"),
        &accepted_stage_name(step, stage, "lift_over_v_slack"),
        &accepted_velocity_bound(),
        &accepted_stage_name(step, stage, "lift_over_v"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(gravity_name()),
            signal_expr(&accepted_stage_cos_gamma_name(step, stage)),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "g_cos_gamma"),
        &accepted_stage_name(step, stage, "g_cos_gamma_remainder"),
        &accepted_stage_name(step, stage, "g_cos_gamma_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "g_cos_gamma"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "g_cos_gamma")),
            const_expr(&accepted_scale()),
        ),
        signal_expr(&stage_v),
        &accepted_stage_name(step, stage, "gcos_over_v"),
        &accepted_stage_name(step, stage, "gcos_over_v_remainder"),
        &accepted_stage_name(step, stage, "gcos_over_v_slack"),
        &accepted_velocity_bound(),
        &accepted_stage_name(step, stage, "gcos_over_v"),
    )?;

    let dgamma_accel = accepted_stage_name(step, stage, "dgamma_accel");
    builder.private_signal(&dgamma_accel)?;
    builder.constrain_equal(
        signal_expr(&dgamma_accel),
        sub_expr(
            signal_expr(&accepted_stage_name(step, stage, "lift_over_v")),
            signal_expr(&accepted_stage_name(step, stage, "gcos_over_v")),
        ),
    )?;
    append_signed_bound(
        builder,
        &dgamma_accel,
        &accepted_gamma_delta_bound(),
        &accepted_stage_name(step, stage, "dgamma_accel_bound"),
    )?;
    builder.private_signal(&accepted_stage_dgamma_name(step, stage))?;
    builder.constrain_equal(
        signal_expr(&accepted_stage_dgamma_name(step, stage)),
        signal_expr(&dgamma_accel),
    )?;
    append_signed_bound(
        builder,
        &accepted_stage_dgamma_name(step, stage),
        &accepted_gamma_delta_bound(),
        &accepted_stage_name(step, stage, "dgamma_bound"),
    )?;

    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_rho_name(step, stage)),
            const_expr(&accepted_scale()),
        ),
        signal_expr(rn_name()),
        &accepted_stage_name(step, stage, "rho_over_rn"),
        &accepted_stage_name(step, stage, "rho_over_rn_remainder"),
        &accepted_stage_name(step, stage, "rho_over_rn_slack"),
        &accepted_nose_radius_bound(),
        &accepted_stage_name(step, stage, "rho_over_rn"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_name(step, stage, "rho_over_rn"),
        &accepted_rho_over_rn_bound(),
        &accepted_stage_name(step, stage, "rho_over_rn_bound"),
    )?;
    append_floor_sqrt_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "rho_over_rn")),
            const_expr(&accepted_scale()),
        ),
        &accepted_stage_name(step, stage, "sqrt_rho_over_rn"),
        &accepted_stage_name(step, stage, "sqrt_rho_over_rn_remainder"),
        &accepted_stage_name(step, stage, "sqrt_rho_over_rn_upper_slack"),
        &accepted_sqrt_rho_over_rn_bound(),
        &sqrt_support_bound(&accepted_sqrt_rho_over_rn_bound()),
        &accepted_stage_name(step, stage, "sqrt_rho_over_rn"),
    )?;
    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(k_sg_name()),
            signal_expr(&accepted_stage_name(step, stage, "sqrt_rho_over_rn")),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_name(step, stage, "heating_factor"),
        &accepted_stage_name(step, stage, "heating_factor_remainder"),
        &accepted_stage_name(step, stage, "heating_factor_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "heating_factor"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_name(step, stage, "heating_factor"),
        &accepted_heating_factor_bound(),
        &accepted_stage_name(step, stage, "heating_factor_bound"),
    )?;
    append_exact_division_constraints(
        builder,
        mul_expr(
            signal_expr(&accepted_stage_name(step, stage, "heating_factor")),
            signal_expr(&accepted_stage_name(step, stage, "v_cubed_fp")),
        ),
        const_expr(&accepted_scale()),
        &accepted_stage_q_dot_name(step, stage),
        &accepted_stage_name(step, stage, "q_dot_remainder"),
        &accepted_stage_name(step, stage, "q_dot_slack"),
        &accepted_scale(),
        &accepted_stage_name(step, stage, "q_dot"),
    )?;
    append_nonnegative_bound(
        builder,
        &accepted_stage_q_dot_name(step, stage),
        &accepted_q_dot_max_bound(),
        &accepted_stage_name(step, stage, "q_dot_bound"),
    )?;

    append_geq_comparator_bit(
        builder,
        signal_expr(q_max_name()),
        signal_expr(&accepted_stage_q_name(step, stage)),
        &accepted_stage_q_ok_name(step, stage),
        &accepted_stage_name(step, stage, "q_ok_slack"),
        &accepted_positive_comparison_offset(&accepted_q_max_bound()),
        &accepted_stage_name(step, stage, "q_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(q_dot_max_name()),
        signal_expr(&accepted_stage_q_dot_name(step, stage)),
        &accepted_stage_q_dot_ok_name(step, stage),
        &accepted_stage_name(step, stage, "q_dot_ok_slack"),
        &accepted_positive_comparison_offset(&accepted_q_dot_max_bound()),
        &accepted_stage_name(step, stage, "q_dot_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(&stage_h),
        signal_expr(h_min_name()),
        &accepted_stage_altitude_ok_name(step, stage),
        &accepted_stage_name(step, stage, "altitude_ok_slack"),
        &accepted_positive_comparison_offset(&accepted_altitude_bound()),
        &accepted_stage_name(step, stage, "altitude_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(v_max_name()),
        signal_expr(&stage_v),
        &accepted_stage_velocity_ok_name(step, stage),
        &accepted_stage_name(step, stage, "velocity_ok_slack"),
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "velocity_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(&stage_gamma),
        sub_expr(const_expr(&zero()), signal_expr(gamma_bound_name())),
        &accepted_stage_gamma_lower_ok_name(step, stage),
        &accepted_stage_name(step, stage, "gamma_lower_ok_slack"),
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "gamma_lower_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(gamma_bound_name()),
        signal_expr(&stage_gamma),
        &accepted_stage_gamma_upper_ok_name(step, stage),
        &accepted_stage_name(step, stage, "gamma_upper_ok_slack"),
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "gamma_upper_ok"),
    )?;
    append_boolean_and(
        builder,
        &accepted_stage_gamma_ok_name(step, stage),
        &accepted_stage_gamma_lower_ok_name(step, stage),
        &accepted_stage_gamma_upper_ok_name(step, stage),
    )?;
    let nominal_q_chain = accepted_stage_name(step, stage, "nominal_q_chain");
    append_boolean_and(
        builder,
        &nominal_q_chain,
        &accepted_stage_q_ok_name(step, stage),
        &accepted_stage_q_dot_ok_name(step, stage),
    )?;
    let nominal_state_chain = accepted_stage_name(step, stage, "nominal_state_chain");
    append_boolean_and(
        builder,
        &nominal_state_chain,
        &accepted_stage_altitude_ok_name(step, stage),
        &accepted_stage_velocity_ok_name(step, stage),
    )?;
    let nominal_gamma_chain = accepted_stage_name(step, stage, "nominal_gamma_chain");
    append_boolean_and(
        builder,
        &nominal_gamma_chain,
        &nominal_state_chain,
        &accepted_stage_gamma_ok_name(step, stage),
    )?;
    append_boolean_and(
        builder,
        &accepted_stage_nominal_ok_name(step, stage),
        &nominal_q_chain,
        &nominal_gamma_chain,
    )?;

    append_geq_comparator_bit(
        builder,
        signal_expr(&stage_v),
        signal_expr(&abort_selected_fields[2]),
        &accepted_stage_abort_velocity_ok_name(step, stage),
        &accepted_stage_name(step, stage, "abort_velocity_min_slack"),
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "abort_velocity_min_ok"),
    )?;
    let abort_velocity_upper_ok = accepted_stage_name(step, stage, "abort_velocity_upper_ok");
    append_geq_comparator_bit(
        builder,
        signal_expr(&abort_selected_fields[3]),
        signal_expr(&stage_v),
        &abort_velocity_upper_ok,
        &accepted_stage_name(step, stage, "abort_velocity_max_slack"),
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "abort_velocity_max_ok"),
    )?;
    let abort_velocity_ok = accepted_stage_name(step, stage, "abort_velocity_ok");
    append_boolean_and(
        builder,
        &abort_velocity_ok,
        &accepted_stage_abort_velocity_ok_name(step, stage),
        &abort_velocity_upper_ok,
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(&stage_gamma),
        signal_expr(&abort_selected_fields[4]),
        &accepted_stage_abort_gamma_lower_ok_name(step, stage),
        &accepted_stage_name(step, stage, "abort_gamma_lower_slack"),
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "abort_gamma_lower_ok"),
    )?;
    append_geq_comparator_bit(
        builder,
        signal_expr(&abort_selected_fields[5]),
        signal_expr(&stage_gamma),
        &accepted_stage_abort_gamma_upper_ok_name(step, stage),
        &accepted_stage_name(step, stage, "abort_gamma_upper_slack"),
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "abort_gamma_upper_ok"),
    )?;
    append_boolean_and(
        builder,
        &accepted_stage_abort_gamma_ok_name(step, stage),
        &accepted_stage_abort_gamma_lower_ok_name(step, stage),
        &accepted_stage_abort_gamma_upper_ok_name(step, stage),
    )?;
    append_boolean_and(
        builder,
        &accepted_stage_abort_ok_name(step, stage),
        &abort_velocity_ok,
        &accepted_stage_abort_gamma_ok_name(step, stage),
    )?;

    Ok(())
}

fn build_private_reentry_thermal_accepted_program_inner(
    shape: &AcceptedReentryShape,
) -> ZkfResult<zkf_core::Program> {
    let mut builder = ProgramBuilder::new(
        format!(
            "private_reentry_thermal_accepted_{}_{}_{}_{}",
            shape.steps, shape.atmosphere_rows, shape.sine_rows, shape.abort_rows
        ),
        REENTRY_APP_FIELD,
    );
    let builder = &mut builder;
    builder.metadata_entry("application", "private-reentry-mission-assurance")?;
    builder.metadata_entry("integration_steps", shape.steps.to_string())?;
    builder.metadata_entry("integrator", "rk4")?;
    builder.metadata_entry("time_step_seconds", "1")?;
    builder.metadata_entry("fixed_point_scale", accepted_scale().to_str_radix(10))?;
    builder.metadata_entry("accepted_backend", "plonky3")?;
    builder.metadata_entry("theorem_lane", "transparent-fixed-policy-cpu")?;
    builder.metadata_entry(
        "model_revision",
        "reentry-mission-pack-v2-rk4-private-table-abort",
    )?;
    builder.metadata_entry(
        "mathematical_model",
        "fixed-horizon reduced-order RK4 reentry certificate with private-table interpolation, full-state commitments, and mechanized nominal-or-valid-abort semantics",
    )?;
    builder.metadata_entry(
        "accepted_assumptions",
        "initial_downrange=0, initial_cumulative_heat=0, CPU-first fixed policy",
    )?;

    for public_name in [
        q_max_name(),
        q_dot_max_name(),
        h_min_name(),
        v_max_name(),
        gamma_bound_name(),
        gravity_name(),
        k_sg_name(),
    ] {
        builder.public_input(public_name)?;
    }
    append_nonnegative_bound(
        builder,
        q_max_name(),
        &accepted_q_max_bound(),
        "accepted_q_max",
    )?;
    append_nonnegative_bound(
        builder,
        q_dot_max_name(),
        &accepted_q_dot_max_bound(),
        "accepted_q_dot_max",
    )?;
    append_nonnegative_bound(
        builder,
        h_min_name(),
        &accepted_altitude_bound(),
        "accepted_h_min",
    )?;
    append_nonnegative_bound(
        builder,
        v_max_name(),
        &accepted_velocity_bound(),
        "accepted_v_max",
    )?;
    append_nonnegative_bound(
        builder,
        gamma_bound_name(),
        &accepted_gamma_bound(),
        "accepted_gamma_bound",
    )?;
    append_nonnegative_bound(
        builder,
        gravity_name(),
        &accepted_gravity_bound(),
        "accepted_g0",
    )?;
    append_nonnegative_bound(
        builder,
        k_sg_name(),
        &accepted_k_sg_bound(),
        "accepted_k_sg",
    )?;
    for signal in [
        q_max_name(),
        q_dot_max_name(),
        v_max_name(),
        gamma_bound_name(),
        gravity_name(),
        k_sg_name(),
    ] {
        append_nonzero_constraint(builder, signal, &format!("{signal}_accepted_nonzero"))?;
    }

    for signal in [
        altitude_name(),
        velocity_name(),
        gamma_name(),
        mass_input_name(),
        sref_name(),
        cd_name(),
        cl_name(),
        rn_name(),
    ] {
        builder.private_input(signal)?;
    }
    append_nonnegative_bound(
        builder,
        altitude_name(),
        &accepted_altitude_bound(),
        "accepted_h0",
    )?;
    append_nonnegative_bound(
        builder,
        velocity_name(),
        &accepted_velocity_bound(),
        "accepted_v0",
    )?;
    append_nonzero_constraint(builder, velocity_name(), "accepted_v0_nonzero")?;
    append_signed_bound(
        builder,
        gamma_name(),
        &accepted_gamma_bound(),
        "accepted_gamma0",
    )?;
    append_nonnegative_bound(
        builder,
        mass_input_name(),
        &accepted_mass_bound(),
        "accepted_mass",
    )?;
    append_nonzero_constraint(builder, mass_input_name(), "accepted_mass_nonzero")?;
    append_nonnegative_bound(
        builder,
        sref_name(),
        &accepted_area_bound(),
        "accepted_sref",
    )?;
    append_nonzero_constraint(builder, sref_name(), "accepted_sref_nonzero")?;
    append_nonnegative_bound(builder, cd_name(), &accepted_coeff_bound(), "accepted_cd")?;
    append_nonnegative_bound(builder, cl_name(), &accepted_coeff_bound(), "accepted_cl")?;
    append_nonnegative_bound(
        builder,
        rn_name(),
        &accepted_nose_radius_bound(),
        "accepted_rn",
    )?;
    append_nonzero_constraint(builder, rn_name(), "accepted_rn_nonzero")?;

    builder.constant_signal(accepted_downrange_state_name(0), FieldElement::ZERO)?;
    builder.constant_signal(accepted_heat_state_name(0), FieldElement::ZERO)?;
    builder.constant_signal(accepted_abort_latch_state_name(0), FieldElement::ZERO)?;

    for step in 0..shape.steps {
        builder.private_input(bank_cos_name(step))?;
        append_signed_bound(
            builder,
            &bank_cos_name(step),
            &accepted_bank_cos_bound(),
            &format!("accepted_step_{step}_bank_cos"),
        )?;
    }

    for row in 0..shape.atmosphere_rows {
        let row_inputs = accepted_atmosphere_row_input_names(row);
        for name in &row_inputs {
            builder.private_input(name)?;
        }
        append_nonnegative_bound(
            builder,
            &row_inputs[0],
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_start"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[1],
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_end"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[2],
            &accepted_density_bound(),
            &format!("accepted_atmosphere_row_{row}_density_start"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[3],
            &accepted_density_bound(),
            &format!("accepted_atmosphere_row_{row}_density_end"),
        )?;
        let span = format!("accepted_atmosphere_row_{row}_span");
        builder.private_signal(&span)?;
        builder.constrain_equal(
            signal_expr(&span),
            sub_expr(signal_expr(&row_inputs[1]), signal_expr(&row_inputs[0])),
        )?;
        append_nonnegative_bound(
            builder,
            &span,
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_span"),
        )?;
        append_nonzero_constraint(
            builder,
            &span,
            &format!("accepted_atmosphere_row_{row}_span"),
        )?;
        if row + 1 < shape.atmosphere_rows {
            let order = format!("accepted_atmosphere_row_{row}_order");
            builder.private_signal(&order)?;
            builder.constrain_equal(
                signal_expr(&order),
                sub_expr(
                    signal_expr(&accepted_atmosphere_altitude_start_name(row + 1)),
                    signal_expr(&row_inputs[1]),
                ),
            )?;
            append_nonnegative_bound(
                builder,
                &order,
                &accepted_altitude_bound(),
                &format!("accepted_atmosphere_row_{row}_order"),
            )?;
        }
    }

    for row in 0..shape.sine_rows {
        let row_inputs = accepted_sine_row_input_names(row);
        for name in &row_inputs {
            builder.private_input(name)?;
        }
        append_signed_bound(
            builder,
            &row_inputs[0],
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_start"),
        )?;
        append_signed_bound(
            builder,
            &row_inputs[1],
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_end"),
        )?;
        append_signed_bound(
            builder,
            &row_inputs[2],
            &accepted_trig_bound(),
            &format!("accepted_sine_row_{row}_value_start"),
        )?;
        append_signed_bound(
            builder,
            &row_inputs[3],
            &accepted_trig_bound(),
            &format!("accepted_sine_row_{row}_value_end"),
        )?;
        let span = format!("accepted_sine_row_{row}_span");
        builder.private_signal(&span)?;
        builder.constrain_equal(
            signal_expr(&span),
            sub_expr(signal_expr(&row_inputs[1]), signal_expr(&row_inputs[0])),
        )?;
        append_nonnegative_bound(
            builder,
            &span,
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_span"),
        )?;
        append_nonzero_constraint(builder, &span, &format!("accepted_sine_row_{row}_span"))?;
        if row + 1 < shape.sine_rows {
            let order = format!("accepted_sine_row_{row}_order");
            builder.private_signal(&order)?;
            builder.constrain_equal(
                signal_expr(&order),
                sub_expr(
                    signal_expr(&accepted_sine_gamma_start_name(row + 1)),
                    signal_expr(&row_inputs[1]),
                ),
            )?;
            append_nonnegative_bound(
                builder,
                &order,
                &accepted_gamma_bound(),
                &format!("accepted_sine_row_{row}_order"),
            )?;
        }
    }

    for row in 0..shape.abort_rows {
        let row_inputs = accepted_abort_row_input_names(row);
        for name in &row_inputs {
            builder.private_input(name)?;
        }
        append_nonnegative_bound(
            builder,
            &row_inputs[0],
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_altitude_start"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[1],
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_altitude_end"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[2],
            &accepted_velocity_bound(),
            &format!("accepted_abort_row_{row}_velocity_min"),
        )?;
        append_nonnegative_bound(
            builder,
            &row_inputs[3],
            &accepted_velocity_bound(),
            &format!("accepted_abort_row_{row}_velocity_max"),
        )?;
        append_signed_bound(
            builder,
            &row_inputs[4],
            &accepted_gamma_bound(),
            &format!("accepted_abort_row_{row}_gamma_min"),
        )?;
        append_signed_bound(
            builder,
            &row_inputs[5],
            &accepted_gamma_bound(),
            &format!("accepted_abort_row_{row}_gamma_max"),
        )?;
        let span = format!("accepted_abort_row_{row}_span");
        builder.private_signal(&span)?;
        builder.constrain_equal(
            signal_expr(&span),
            sub_expr(signal_expr(&row_inputs[1]), signal_expr(&row_inputs[0])),
        )?;
        append_nonnegative_bound(
            builder,
            &span,
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_span"),
        )?;
        append_nonzero_constraint(builder, &span, &format!("accepted_abort_row_{row}_span"))?;
        if row + 1 < shape.abort_rows {
            let order = format!("accepted_abort_row_{row}_order");
            builder.private_signal(&order)?;
            builder.constrain_equal(
                signal_expr(&order),
                sub_expr(
                    signal_expr(&accepted_abort_altitude_start_name(row + 1)),
                    signal_expr(&row_inputs[1]),
                ),
            )?;
            append_nonnegative_bound(
                builder,
                &order,
                &accepted_altitude_bound(),
                &format!("accepted_abort_row_{row}_order"),
            )?;
        }
    }

    for signal in [
        accepted_abort_q_trigger_name(),
        accepted_abort_q_dot_trigger_name(),
        accepted_abort_altitude_floor_name(),
        accepted_abort_velocity_ceiling_name(),
    ] {
        builder.private_input(signal)?;
    }
    append_nonnegative_bound(
        builder,
        accepted_abort_q_trigger_name(),
        &accepted_q_max_bound(),
        "accepted_abort_q_trigger",
    )?;
    append_nonnegative_bound(
        builder,
        accepted_abort_q_dot_trigger_name(),
        &accepted_q_dot_max_bound(),
        "accepted_abort_q_dot_trigger",
    )?;
    append_nonnegative_bound(
        builder,
        accepted_abort_altitude_floor_name(),
        &accepted_altitude_bound(),
        "accepted_abort_altitude_floor",
    )?;
    append_nonnegative_bound(
        builder,
        accepted_abort_velocity_ceiling_name(),
        &accepted_velocity_bound(),
        "accepted_abort_velocity_ceiling",
    )?;
    append_nonzero_constraint(
        builder,
        accepted_abort_velocity_ceiling_name(),
        "accepted_abort_velocity_ceiling_nonzero",
    )?;

    let mut q_candidates = Vec::with_capacity(shape.steps * 4);
    let mut q_dot_candidates = Vec::with_capacity(shape.steps * 4);

    for step in 0..shape.steps {
        let current_h = h_state_name(step);
        let current_x = accepted_downrange_state_name(step);
        let current_v = v_state_name(step);
        let current_gamma = gamma_state_name(step);
        let current_heat = accepted_heat_state_name(step);
        let current_abort = accepted_abort_latch_state_name(step);
        if step > 0 {
            builder.constrain_boolean(&current_abort)?;
        }

        for stage in 1..=4 {
            builder.private_signal(accepted_stage_altitude_name(step, stage))?;
            builder.private_signal(accepted_stage_downrange_name(step, stage))?;
            builder.private_signal(accepted_stage_velocity_name(step, stage))?;
            builder.private_signal(accepted_stage_gamma_name(step, stage))?;
            builder.private_signal(accepted_stage_heat_name(step, stage))?;
        }
        builder.constrain_equal(
            signal_expr(&accepted_stage_altitude_name(step, 1)),
            signal_expr(&current_h),
        )?;
        builder.constrain_equal(
            signal_expr(&accepted_stage_downrange_name(step, 1)),
            signal_expr(&current_x),
        )?;
        builder.constrain_equal(
            signal_expr(&accepted_stage_velocity_name(step, 1)),
            signal_expr(&current_v),
        )?;
        builder.constrain_equal(
            signal_expr(&accepted_stage_gamma_name(step, 1)),
            signal_expr(&current_gamma),
        )?;
        builder.constrain_equal(
            signal_expr(&accepted_stage_heat_name(step, 1)),
            signal_expr(&current_heat),
        )?;

        for (stage, source_stage) in [(2usize, 1usize), (3usize, 2usize)] {
            for (suffix, current_signal, derivative_signal) in [
                (
                    "h_half",
                    current_h.as_str(),
                    accepted_stage_dh_name(step, source_stage),
                ),
                (
                    "x_half",
                    current_x.as_str(),
                    accepted_stage_dx_name(step, source_stage),
                ),
                (
                    "v_half",
                    current_v.as_str(),
                    accepted_stage_dv_name(step, source_stage),
                ),
                (
                    "gamma_half",
                    current_gamma.as_str(),
                    accepted_stage_dgamma_name(step, source_stage),
                ),
                (
                    "heat_half",
                    current_heat.as_str(),
                    accepted_stage_q_dot_name(step, source_stage),
                ),
            ] {
                append_exact_division_constraints(
                    builder,
                    signal_expr(&derivative_signal),
                    const_expr(&two()),
                    &accepted_stage_name(step, stage, suffix),
                    &accepted_stage_name(step, stage, &format!("{suffix}_remainder")),
                    &accepted_stage_name(step, stage, &format!("{suffix}_slack")),
                    &two(),
                    &accepted_stage_name(step, stage, suffix),
                )?;
                let target = match suffix {
                    "h_half" => accepted_stage_altitude_name(step, stage),
                    "x_half" => accepted_stage_downrange_name(step, stage),
                    "v_half" => accepted_stage_velocity_name(step, stage),
                    "gamma_half" => accepted_stage_gamma_name(step, stage),
                    _ => accepted_stage_heat_name(step, stage),
                };
                builder.constrain_equal(
                    signal_expr(&target),
                    add_expr(vec![
                        signal_expr(current_signal),
                        signal_expr(&accepted_stage_name(step, stage, suffix)),
                    ]),
                )?;
            }
        }

        for (target, current_signal, derivative_signal) in [
            (
                accepted_stage_altitude_name(step, 4),
                current_h.clone(),
                accepted_stage_dh_name(step, 3),
            ),
            (
                accepted_stage_downrange_name(step, 4),
                current_x.clone(),
                accepted_stage_dx_name(step, 3),
            ),
            (
                accepted_stage_velocity_name(step, 4),
                current_v.clone(),
                accepted_stage_dv_name(step, 3),
            ),
            (
                accepted_stage_gamma_name(step, 4),
                current_gamma.clone(),
                accepted_stage_dgamma_name(step, 3),
            ),
            (
                accepted_stage_heat_name(step, 4),
                current_heat.clone(),
                accepted_stage_q_dot_name(step, 3),
            ),
        ] {
            builder.constrain_equal(
                signal_expr(&target),
                add_expr(vec![
                    signal_expr(&current_signal),
                    signal_expr(&derivative_signal),
                ]),
            )?;
        }

        for stage in 1..=4 {
            append_accepted_stage_constraints(builder, shape, step, stage)?;
            q_candidates.push(accepted_stage_q_name(step, stage));
            q_dot_candidates.push(accepted_stage_q_dot_name(step, stage));
        }

        for (label, source_names) in [
            (
                "dh",
                vec![
                    accepted_stage_dh_name(step, 1),
                    accepted_stage_dh_name(step, 2),
                    accepted_stage_dh_name(step, 3),
                    accepted_stage_dh_name(step, 4),
                ],
            ),
            (
                "dx",
                vec![
                    accepted_stage_dx_name(step, 1),
                    accepted_stage_dx_name(step, 2),
                    accepted_stage_dx_name(step, 3),
                    accepted_stage_dx_name(step, 4),
                ],
            ),
            (
                "dv",
                vec![
                    accepted_stage_dv_name(step, 1),
                    accepted_stage_dv_name(step, 2),
                    accepted_stage_dv_name(step, 3),
                    accepted_stage_dv_name(step, 4),
                ],
            ),
            (
                "dgamma",
                vec![
                    accepted_stage_dgamma_name(step, 1),
                    accepted_stage_dgamma_name(step, 2),
                    accepted_stage_dgamma_name(step, 3),
                    accepted_stage_dgamma_name(step, 4),
                ],
            ),
            (
                "dheat",
                vec![
                    accepted_stage_q_dot_name(step, 1),
                    accepted_stage_q_dot_name(step, 2),
                    accepted_stage_q_dot_name(step, 3),
                    accepted_stage_q_dot_name(step, 4),
                ],
            ),
        ] {
            append_exact_division_constraints(
                builder,
                add_expr(vec![
                    signal_expr(&source_names[0]),
                    mul_expr(const_expr(&two()), signal_expr(&source_names[1])),
                    mul_expr(const_expr(&two()), signal_expr(&source_names[2])),
                    signal_expr(&source_names[3]),
                ]),
                const_expr(&BigInt::from(6u8)),
                &accepted_weighted_delta_name(step, label),
                &accepted_stage_name(step, 0, &format!("weighted_{label}_remainder")),
                &accepted_stage_name(step, 0, &format!("weighted_{label}_slack")),
                &BigInt::from(6u8),
                &accepted_stage_name(step, 0, &format!("weighted_{label}")),
            )?;
            let weighted_anchor = nonlinear_anchor_name(&accepted_weighted_delta_name(step, label));
            builder.private_signal(&weighted_anchor)?;
            builder.constrain_equal(
                signal_expr(&weighted_anchor),
                mul_expr(
                    signal_expr(&accepted_weighted_delta_name(step, label)),
                    signal_expr(&accepted_weighted_delta_name(step, label)),
                ),
            )?;
        }

        let next_h = h_state_name(step + 1);
        let next_x = accepted_downrange_state_name(step + 1);
        let next_v = v_state_name(step + 1);
        let next_gamma = gamma_state_name(step + 1);
        let next_heat = accepted_heat_state_name(step + 1);
        let next_abort = accepted_abort_latch_state_name(step + 1);
        builder.private_signal(&next_h)?;
        builder.private_signal(&next_x)?;
        builder.private_signal(&next_v)?;
        builder.private_signal(&next_gamma)?;
        builder.private_signal(&next_heat)?;
        builder.private_signal(&next_abort)?;
        builder.constrain_boolean(&next_abort)?;
        builder.constrain_equal(
            signal_expr(&next_h),
            add_expr(vec![
                signal_expr(&current_h),
                signal_expr(&accepted_weighted_delta_name(step, "dh")),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_x),
            add_expr(vec![
                signal_expr(&current_x),
                signal_expr(&accepted_weighted_delta_name(step, "dx")),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_v),
            add_expr(vec![
                signal_expr(&current_v),
                signal_expr(&accepted_weighted_delta_name(step, "dv")),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_gamma),
            add_expr(vec![
                signal_expr(&current_gamma),
                signal_expr(&accepted_weighted_delta_name(step, "dgamma")),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_heat),
            add_expr(vec![
                signal_expr(&current_heat),
                signal_expr(&accepted_weighted_delta_name(step, "dheat")),
            ]),
        )?;
        append_nonnegative_bound(
            builder,
            &next_h,
            &accepted_altitude_bound(),
            &format!("accepted_state_{}_h", step + 1),
        )?;
        append_nonnegative_bound(
            builder,
            &next_x,
            &accepted_downrange_bound(),
            &format!("accepted_state_{}_x", step + 1),
        )?;
        append_nonnegative_bound(
            builder,
            &next_v,
            &accepted_velocity_bound(),
            &format!("accepted_state_{}_v", step + 1),
        )?;
        append_nonzero_constraint(
            builder,
            &next_v,
            &format!("accepted_state_{}_v_nonzero", step + 1),
        )?;
        append_signed_bound(
            builder,
            &next_gamma,
            &accepted_gamma_bound(),
            &format!("accepted_state_{}_gamma", step + 1),
        )?;
        append_nonnegative_bound(
            builder,
            &next_heat,
            &accepted_heat_bound(),
            &format!("accepted_state_{}_heat", step + 1),
        )?;

        let mut q_predicate_bits = Vec::new();
        let mut q_dot_predicate_bits = Vec::new();
        let mut nominal_stage_bits = Vec::new();
        let mut abort_stage_bits = Vec::new();
        for stage in 1..=4 {
            let q_predicate_bit = accepted_stage_name(step, stage, "abort_q_predicate");
            append_geq_comparator_bit(
                builder,
                signal_expr(&accepted_stage_q_name(step, stage)),
                signal_expr(accepted_abort_q_trigger_name()),
                &q_predicate_bit,
                &accepted_stage_name(step, stage, "abort_q_predicate_slack"),
                &accepted_positive_comparison_offset(&accepted_q_max_bound()),
                &accepted_stage_name(step, stage, "abort_q_predicate"),
            )?;
            q_predicate_bits.push(q_predicate_bit);

            let q_dot_predicate_bit = accepted_stage_name(step, stage, "abort_q_dot_predicate");
            append_geq_comparator_bit(
                builder,
                signal_expr(&accepted_stage_q_dot_name(step, stage)),
                signal_expr(accepted_abort_q_dot_trigger_name()),
                &q_dot_predicate_bit,
                &accepted_stage_name(step, stage, "abort_q_dot_predicate_slack"),
                &accepted_positive_comparison_offset(&accepted_q_dot_max_bound()),
                &accepted_stage_name(step, stage, "abort_q_dot_predicate"),
            )?;
            q_dot_predicate_bits.push(q_dot_predicate_bit);
            nominal_stage_bits.push(accepted_stage_nominal_ok_name(step, stage));
            abort_stage_bits.push(accepted_stage_abort_ok_name(step, stage));
        }

        let q_abort_predicate = accepted_q_abort_predicate_name(step);
        let q_abort_chain = accepted_stage_name(step, 0, "abort_q_chain");
        append_boolean_or(
            builder,
            &q_abort_chain,
            &q_predicate_bits[0],
            &q_predicate_bits[1],
        )?;
        let q_abort_chain_2 = accepted_stage_name(step, 0, "abort_q_chain_2");
        append_boolean_or(
            builder,
            &q_abort_chain_2,
            &q_abort_chain,
            &q_predicate_bits[2],
        )?;
        append_boolean_or(
            builder,
            &q_abort_predicate,
            &q_abort_chain_2,
            &q_predicate_bits[3],
        )?;

        let q_dot_abort_predicate = accepted_q_dot_abort_predicate_name(step);
        let q_dot_abort_chain = accepted_stage_name(step, 0, "abort_q_dot_chain");
        append_boolean_or(
            builder,
            &q_dot_abort_chain,
            &q_dot_predicate_bits[0],
            &q_dot_predicate_bits[1],
        )?;
        let q_dot_abort_chain_2 = accepted_stage_name(step, 0, "abort_q_dot_chain_2");
        append_boolean_or(
            builder,
            &q_dot_abort_chain_2,
            &q_dot_abort_chain,
            &q_dot_predicate_bits[2],
        )?;
        append_boolean_or(
            builder,
            &q_dot_abort_predicate,
            &q_dot_abort_chain_2,
            &q_dot_predicate_bits[3],
        )?;

        append_geq_comparator_bit(
            builder,
            signal_expr(accepted_abort_altitude_floor_name()),
            signal_expr(&next_h),
            &accepted_altitude_abort_predicate_name(step),
            &accepted_stage_name(step, 0, "abort_altitude_slack"),
            &accepted_positive_comparison_offset(&accepted_altitude_bound()),
            &accepted_stage_name(step, 0, "abort_altitude"),
        )?;
        append_geq_comparator_bit(
            builder,
            signal_expr(&next_v),
            signal_expr(accepted_abort_velocity_ceiling_name()),
            &accepted_velocity_abort_predicate_name(step),
            &accepted_stage_name(step, 0, "abort_velocity_slack"),
            &accepted_positive_comparison_offset(&accepted_velocity_bound()),
            &accepted_stage_name(step, 0, "abort_velocity"),
        )?;

        let trigger_chain = accepted_stage_name(step, 0, "trigger_chain");
        append_boolean_or(
            builder,
            &trigger_chain,
            &q_abort_predicate,
            &q_dot_abort_predicate,
        )?;
        let trigger_chain_2 = accepted_stage_name(step, 0, "trigger_chain_2");
        append_boolean_or(
            builder,
            &trigger_chain_2,
            &trigger_chain,
            &accepted_altitude_abort_predicate_name(step),
        )?;
        append_boolean_or(
            builder,
            &accepted_trigger_name(step),
            &trigger_chain_2,
            &accepted_velocity_abort_predicate_name(step),
        )?;

        let nominal_chain = accepted_stage_name(step, 0, "nominal_chain");
        append_boolean_and(
            builder,
            &nominal_chain,
            &nominal_stage_bits[0],
            &nominal_stage_bits[1],
        )?;
        let nominal_chain_2 = accepted_stage_name(step, 0, "nominal_chain_2");
        append_boolean_and(
            builder,
            &nominal_chain_2,
            &nominal_chain,
            &nominal_stage_bits[2],
        )?;
        append_boolean_and(
            builder,
            &accepted_nominal_ok_name(step),
            &nominal_chain_2,
            &nominal_stage_bits[3],
        )?;

        let abort_chain = accepted_stage_name(step, 0, "abort_chain");
        append_boolean_and(
            builder,
            &abort_chain,
            &abort_stage_bits[0],
            &abort_stage_bits[1],
        )?;
        let abort_chain_2 = accepted_stage_name(step, 0, "abort_chain_2");
        append_boolean_and(builder, &abort_chain_2, &abort_chain, &abort_stage_bits[2])?;
        append_boolean_and(
            builder,
            &accepted_abort_ok_name(step),
            &abort_chain_2,
            &abort_stage_bits[3],
        )?;

        let not_current_abort = accepted_stage_name(step, 0, "not_current_abort");
        append_boolean_not(builder, &not_current_abort, &current_abort)?;
        append_boolean_and(
            builder,
            &accepted_first_trigger_name(step),
            &accepted_trigger_name(step),
            &not_current_abort,
        )?;
        append_boolean_or(
            builder,
            &next_abort,
            &current_abort,
            &accepted_trigger_name(step),
        )?;
        let nominal_or_trigger = accepted_stage_name(step, 0, "nominal_or_trigger");
        append_boolean_or(
            builder,
            &nominal_or_trigger,
            &accepted_nominal_ok_name(step),
            &accepted_trigger_name(step),
        )?;
        builder.private_signal(accepted_step_valid_name(step))?;
        builder.constrain_boolean(accepted_step_valid_name(step))?;
        builder.constrain_select(
            &accepted_step_valid_name(step),
            &current_abort,
            signal_expr(&accepted_abort_ok_name(step)),
            signal_expr(&nominal_or_trigger),
        )?;
        builder.constrain_equal(
            signal_expr(&accepted_step_valid_name(step)),
            const_expr(&one()),
        )?;
    }

    let mut current_q_max = q_candidates[0].clone();
    for (index, candidate) in q_candidates.iter().enumerate().skip(1) {
        let target = format!("accepted_peak_q_running_{index}");
        append_pairwise_max_signal(
            builder,
            &target,
            &current_q_max,
            candidate,
            &accepted_dynamic_pressure_bound(),
            &format!("accepted_peak_q_running_{index}"),
        )?;
        current_q_max = target;
    }
    builder.public_output(peak_q_output_name())?;
    builder.constrain_equal(
        signal_expr(peak_q_output_name()),
        signal_expr(&current_q_max),
    )?;

    let mut current_q_dot_max = q_dot_candidates[0].clone();
    for (index, candidate) in q_dot_candidates.iter().enumerate().skip(1) {
        let target = format!("accepted_peak_q_dot_running_{index}");
        append_pairwise_max_signal(
            builder,
            &target,
            &current_q_dot_max,
            candidate,
            &accepted_q_dot_max_bound(),
            &format!("accepted_peak_q_dot_running_{index}"),
        )?;
        current_q_dot_max = target;
    }
    builder.public_output(peak_q_dot_output_name())?;
    builder.constrain_equal(
        signal_expr(peak_q_dot_output_name()),
        signal_expr(&current_q_dot_max),
    )?;

    builder.public_output(trajectory_commitment_output_name())?;
    let mut previous_digest = const_expr(&trajectory_seed_tag());
    for step in 0..=shape.steps {
        let boundary_hi = append_poseidon_hash(
            builder,
            &format!("accepted_boundary_hi_{step}"),
            [
                signal_expr(&h_state_name(step)),
                signal_expr(&accepted_downrange_state_name(step)),
                signal_expr(&v_state_name(step)),
                signal_expr(&gamma_state_name(step)),
            ],
        )?;
        let boundary_lo = append_poseidon_hash(
            builder,
            &format!("accepted_boundary_lo_{step}"),
            [
                signal_expr(&accepted_heat_state_name(step)),
                signal_expr(&accepted_abort_latch_state_name(step)),
                const_expr(&BigInt::from(step as u64)),
                const_expr(&zero()),
            ],
        )?;
        let state_digest = append_poseidon_hash(
            builder,
            &format!("accepted_boundary_state_{step}"),
            [
                signal_expr(&boundary_hi),
                signal_expr(&boundary_lo),
                const_expr(&trajectory_step_tag(step)),
                const_expr(&zero()),
            ],
        )?;
        previous_digest = {
            let chain_digest = append_poseidon_hash(
                builder,
                &format!("accepted_boundary_chain_{step}"),
                [
                    signal_expr(&state_digest),
                    previous_digest,
                    const_expr(&trajectory_step_tag(step)),
                    const_expr(&one()),
                ],
            )?;
            signal_expr(&chain_digest)
        };
    }
    builder.constrain_equal(
        signal_expr(trajectory_commitment_output_name()),
        previous_digest,
    )?;

    builder.public_output(terminal_state_commitment_output_name())?;
    let terminal_hi = append_poseidon_hash(
        builder,
        "accepted_terminal_state_hi",
        [
            signal_expr(&h_state_name(shape.steps)),
            signal_expr(&accepted_downrange_state_name(shape.steps)),
            signal_expr(&v_state_name(shape.steps)),
            signal_expr(&gamma_state_name(shape.steps)),
        ],
    )?;
    let terminal_lo = append_poseidon_hash(
        builder,
        "accepted_terminal_state_lo",
        [
            signal_expr(&accepted_heat_state_name(shape.steps)),
            signal_expr(&accepted_abort_latch_state_name(shape.steps)),
            const_expr(&BigInt::from(shape.steps as u64)),
            const_expr(&terminal_state_tag()),
        ],
    )?;
    let terminal_digest = append_poseidon_hash(
        builder,
        "accepted_terminal_state_commitment",
        [
            signal_expr(&terminal_hi),
            signal_expr(&terminal_lo),
            const_expr(&terminal_state_tag()),
            const_expr(&zero()),
        ],
    )?;
    builder.constrain_equal(
        signal_expr(terminal_state_commitment_output_name()),
        signal_expr(&terminal_digest),
    )?;

    builder.public_output(constraint_satisfaction_output_name())?;
    builder.constrain_boolean(constraint_satisfaction_output_name())?;
    builder.constrain_equal(
        signal_expr(constraint_satisfaction_output_name()),
        const_expr(&one()),
    )?;
    builder.build()
}

pub fn build_private_reentry_thermal_accepted_program_for_mission_pack(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<zkf_core::Program> {
    let shape = accepted_shape_from_mission_pack(mission_pack)?;
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        build_private_reentry_thermal_accepted_program_inner(&shape)
    })
}

fn write_exact_division_support(
    values: &mut BTreeMap<String, FieldElement>,
    quotient_name: impl Into<String>,
    quotient: &BigInt,
    remainder_name: impl Into<String>,
    remainder: &BigInt,
    slack_name: impl Into<String>,
    slack: &BigInt,
    prefix: &str,
) {
    write_value(values, quotient_name, quotient.clone());
    write_value(values, remainder_name, remainder.clone());
    write_value(values, slack_name, slack.clone());
    write_exact_division_slack_anchor(values, prefix, slack);
}

fn write_geq_comparator_support(
    values: &mut BTreeMap<String, FieldElement>,
    bit_signal: impl Into<String>,
    slack_signal: impl Into<String>,
    lhs: &BigInt,
    rhs: &BigInt,
    offset: &BigInt,
    prefix: &str,
) -> ZkfResult<bool> {
    let bit = geq_bit(lhs, rhs);
    let slack = comparator_slack(lhs, rhs, offset);
    write_bool_value(values, bit_signal, bit);
    write_nonnegative_bound_support(
        values,
        slack_signal,
        &slack,
        &(offset - one()),
        &format!("{prefix}_comparator_slack"),
    )?;
    Ok(bit)
}

fn write_accepted_interpolation_support(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    selection: &AcceptedInterpolationSelection,
    row_count: usize,
    selector_name: impl Fn(usize) -> String,
    selected_fields: [String; 4],
    interpolated_signal: String,
    input_bound: &BigInt,
    output_bound: &BigInt,
    output_signed: bool,
) -> ZkfResult<()> {
    for row in 0..row_count {
        write_bool_value(values, selector_name(row), row == selection.row_index);
    }
    write_value(
        values,
        selected_fields[0].clone(),
        selection.input_start.clone(),
    );
    write_value(
        values,
        selected_fields[1].clone(),
        selection.input_end.clone(),
    );
    write_value(
        values,
        selected_fields[2].clone(),
        selection.value_start.clone(),
    );
    write_value(
        values,
        selected_fields[3].clone(),
        selection.value_end.clone(),
    );

    write_nonnegative_bound_support(
        values,
        format!("{prefix}_span"),
        &selection.span,
        input_bound,
        &format!("{prefix}_span"),
    )?;
    write_nonzero_inverse_support(values, &selection.span, &format!("{prefix}_span"))?;
    write_nonnegative_bound_support(
        values,
        format!("{prefix}_offset"),
        &selection.offset,
        input_bound,
        &format!("{prefix}_offset"),
    )?;
    write_nonnegative_bound_support(
        values,
        format!("{prefix}_upper_slack"),
        &selection.upper_slack,
        input_bound,
        &format!("{prefix}_upper"),
    )?;
    write_value(values, format!("{prefix}_delta"), selection.delta.clone());
    if output_signed {
        write_signed_bound_support(
            values,
            &selection.delta,
            &(output_bound * BigInt::from(2u8)),
            &format!("{prefix}_delta"),
        )?;
    } else {
        write_nonnegative_bound_support(
            values,
            format!("{prefix}_delta"),
            &selection.delta,
            output_bound,
            &format!("{prefix}_delta"),
        )?;
    }
    write_exact_division_support(
        values,
        format!("{prefix}_quotient"),
        &selection.quotient,
        format!("{prefix}_remainder"),
        &selection.remainder,
        format!("{prefix}_remainder_slack"),
        &selection.slack,
        prefix,
    );
    write_value(
        values,
        interpolated_signal.clone(),
        selection.interpolated.clone(),
    );
    if output_signed {
        write_signed_bound_support(
            values,
            &selection.interpolated,
            output_bound,
            &format!("{prefix}_value"),
        )?;
    } else {
        write_nonnegative_bound_support(
            values,
            interpolated_signal,
            &selection.interpolated,
            output_bound,
            &format!("{prefix}_value"),
        )?;
    }
    Ok(())
}

fn write_accepted_abort_selection_support(
    values: &mut BTreeMap<String, FieldElement>,
    step: usize,
    stage: usize,
    selection: &AcceptedAbortSelection,
    row_count: usize,
) -> ZkfResult<()> {
    for row in 0..row_count {
        write_bool_value(
            values,
            accepted_stage_abort_selector_name(step, stage, row),
            row == selection.row_index,
        );
    }
    write_value(
        values,
        accepted_stage_selected_abort_altitude_start_name(step, stage),
        selection.altitude_start.clone(),
    );
    write_value(
        values,
        accepted_stage_selected_abort_altitude_end_name(step, stage),
        selection.altitude_end.clone(),
    );
    write_value(
        values,
        accepted_stage_selected_abort_velocity_min_name(step, stage),
        selection.velocity_min.clone(),
    );
    write_value(
        values,
        accepted_stage_selected_abort_velocity_max_name(step, stage),
        selection.velocity_max.clone(),
    );
    write_value(
        values,
        accepted_stage_selected_abort_gamma_min_name(step, stage),
        selection.gamma_min.clone(),
    );
    write_value(
        values,
        accepted_stage_selected_abort_gamma_max_name(step, stage),
        selection.gamma_max.clone(),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "abort_lower_slack"),
        &selection.lower_slack,
        &accepted_altitude_bound(),
        &format!("{}_abort_lower", accepted_stage_prefix(step, stage)),
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "abort_upper_slack"),
        &selection.upper_slack,
        &accepted_altitude_bound(),
        &format!("{}_abort_upper", accepted_stage_prefix(step, stage)),
    )?;
    Ok(())
}

fn write_accepted_stage_support(
    values: &mut BTreeMap<String, FieldElement>,
    step: usize,
    stage: usize,
    stage_eval: &AcceptedStageEvaluation,
    current_abort_latch: bool,
    shape: &AcceptedReentryShape,
    parameters: &ReentryPublicParameters,
    abort_thresholds: (&BigInt, &BigInt, &BigInt, &BigInt),
) -> ZkfResult<()> {
    let stage_prefix = accepted_stage_prefix(step, stage);

    write_nonnegative_bound_support(
        values,
        accepted_stage_altitude_name(step, stage),
        &stage_eval.altitude,
        &accepted_altitude_bound(),
        &format!("{stage_prefix}_h_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_downrange_name(step, stage),
        &stage_eval.downrange,
        &accepted_downrange_bound(),
        &format!("{stage_prefix}_x_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_velocity_name(step, stage),
        &stage_eval.velocity,
        &accepted_velocity_bound(),
        &format!("{stage_prefix}_v_bound"),
    )?;
    write_nonzero_inverse_support(
        values,
        &stage_eval.velocity,
        &format!("{stage_prefix}_v_nonzero"),
    )?;
    write_value(
        values,
        accepted_stage_gamma_name(step, stage),
        stage_eval.gamma.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.gamma,
        &accepted_gamma_bound(),
        &format!("{stage_prefix}_gamma_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_heat_name(step, stage),
        &stage_eval.heat,
        &accepted_heat_bound(),
        &format!("{stage_prefix}_heat_bound"),
    )?;

    write_accepted_interpolation_support(
        values,
        &accepted_stage_name(step, stage, "atmosphere_interp"),
        &stage_eval.atmosphere,
        shape.atmosphere_rows,
        |row| accepted_stage_atmosphere_selector_name(step, stage, row),
        [
            accepted_stage_selected_atmosphere_start_name(step, stage),
            accepted_stage_selected_atmosphere_end_name(step, stage),
            accepted_stage_selected_density_start_name(step, stage),
            accepted_stage_selected_density_end_name(step, stage),
        ],
        accepted_stage_rho_name(step, stage),
        &accepted_altitude_bound(),
        &accepted_density_bound(),
        true,
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_rho_name(step, stage),
        &stage_eval.atmosphere.interpolated,
        &accepted_density_bound(),
        &accepted_stage_name(step, stage, "rho"),
    )?;

    write_accepted_interpolation_support(
        values,
        &accepted_stage_name(step, stage, "sine_interp"),
        &stage_eval.sine,
        shape.sine_rows,
        |row| accepted_stage_sine_selector_name(step, stage, row),
        [
            accepted_stage_selected_sine_start_name(step, stage),
            accepted_stage_selected_sine_end_name(step, stage),
            accepted_stage_selected_sine_value_start_name(step, stage),
            accepted_stage_selected_sine_value_end_name(step, stage),
        ],
        accepted_stage_sin_gamma_name(step, stage),
        &accepted_gamma_bound(),
        &accepted_trig_bound(),
        true,
    )?;

    write_accepted_abort_selection_support(
        values,
        step,
        stage,
        &stage_eval.abort_selection,
        shape.abort_rows,
    )?;

    write_nonnegative_bound_support(
        values,
        accepted_stage_cos_gamma_name(step, stage),
        &stage_eval.cos_gamma,
        &accepted_trig_bound(),
        &format!("{}_sqrt_bound", accepted_stage_name(step, stage, "cos")),
    )?;
    write_value(
        values,
        accepted_stage_cos_remainder_name(step, stage),
        stage_eval.cos_remainder.clone(),
    );
    write_value(
        values,
        accepted_stage_cos_upper_slack_name(step, stage),
        stage_eval.cos_upper_slack.clone(),
    );

    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "v_sq"),
        &stage_eval.v_sq,
        &accepted_v_sq_bound(),
        &accepted_stage_name(step, stage, "v_sq"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "v_sq_fp"),
        &stage_eval.v_sq_fp,
        accepted_stage_name(step, stage, "v_sq_fp_remainder"),
        &stage_eval.v_sq_fp_remainder,
        accepted_stage_name(step, stage, "v_sq_fp_slack"),
        &stage_eval.v_sq_fp_slack,
        &accepted_stage_name(step, stage, "v_sq_fp"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "v_sq_fp"),
        &stage_eval.v_sq_fp,
        &accepted_v_sq_fp_bound(),
        &accepted_stage_name(step, stage, "v_sq_fp_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "v_cubed_fp"),
        &stage_eval.v_cubed_fp,
        accepted_stage_name(step, stage, "v_cubed_fp_remainder"),
        &stage_eval.v_cubed_remainder,
        accepted_stage_name(step, stage, "v_cubed_fp_slack"),
        &stage_eval.v_cubed_slack,
        &accepted_stage_name(step, stage, "v_cubed_fp"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "v_cubed_fp"),
        &stage_eval.v_cubed_fp,
        &accepted_v_cubed_fp_bound(),
        &accepted_stage_name(step, stage, "v_cubed_fp_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "rho_v_sq"),
        &stage_eval.rho_v_sq,
        accepted_stage_name(step, stage, "rho_v_sq_remainder"),
        &stage_eval.rho_v_sq_remainder,
        accepted_stage_name(step, stage, "rho_v_sq_slack"),
        &stage_eval.rho_v_sq_slack,
        &accepted_stage_name(step, stage, "rho_v_sq"),
    );
    write_exact_division_support(
        values,
        accepted_stage_q_name(step, stage),
        &stage_eval.q_i,
        accepted_stage_name(step, stage, "q_remainder"),
        &stage_eval.q_i_remainder,
        accepted_stage_name(step, stage, "q_slack"),
        &stage_eval.q_i_slack,
        &accepted_stage_name(step, stage, "q"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_q_name(step, stage),
        &stage_eval.q_i,
        &accepted_dynamic_pressure_bound(),
        &accepted_stage_name(step, stage, "q_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "drag"),
        &stage_eval.drag_force,
        accepted_stage_name(step, stage, "drag_remainder"),
        &stage_eval.drag_remainder,
        accepted_stage_name(step, stage, "drag_slack"),
        &stage_eval.drag_slack,
        &accepted_stage_name(step, stage, "drag"),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "lift_cos"),
        &stage_eval.lift_cos,
        accepted_stage_name(step, stage, "lift_cos_remainder"),
        &stage_eval.lift_cos_remainder,
        accepted_stage_name(step, stage, "lift_cos_slack"),
        &stage_eval.lift_cos_slack,
        &accepted_stage_name(step, stage, "lift_cos"),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "lift"),
        &stage_eval.lift_force,
        accepted_stage_name(step, stage, "lift_remainder"),
        &stage_eval.lift_remainder,
        accepted_stage_name(step, stage, "lift_slack"),
        &stage_eval.lift_slack,
        &accepted_stage_name(step, stage, "lift"),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "drag_accel"),
        &stage_eval.drag_accel,
        accepted_stage_name(step, stage, "drag_accel_remainder"),
        &stage_eval.drag_accel_remainder,
        accepted_stage_name(step, stage, "drag_accel_slack"),
        &stage_eval.drag_accel_slack,
        &accepted_stage_name(step, stage, "drag_accel"),
    );
    write_value(
        values,
        accepted_stage_name(step, stage, "drag_accel"),
        stage_eval.drag_accel.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.drag_accel,
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "drag_accel_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "lift_accel"),
        &stage_eval.lift_accel,
        accepted_stage_name(step, stage, "lift_accel_remainder"),
        &stage_eval.lift_accel_remainder,
        accepted_stage_name(step, stage, "lift_accel_slack"),
        &stage_eval.lift_accel_slack,
        &accepted_stage_name(step, stage, "lift_accel"),
    );
    write_value(
        values,
        accepted_stage_name(step, stage, "lift_accel"),
        stage_eval.lift_accel.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.lift_accel,
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "lift_accel_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "g_sin_gamma"),
        &stage_eval.g_sin_gamma,
        accepted_stage_name(step, stage, "g_sin_gamma_remainder"),
        &stage_eval.g_sin_gamma_remainder,
        accepted_stage_name(step, stage, "g_sin_gamma_slack"),
        &stage_eval.g_sin_gamma_slack,
        &accepted_stage_name(step, stage, "g_sin_gamma"),
    );
    write_value(
        values,
        accepted_stage_name(step, stage, "dv_accel"),
        stage_eval.dv_accel.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dv_accel,
        &accepted_acceleration_bound(),
        &accepted_stage_name(step, stage, "dv_accel_bound"),
    )?;
    write_value(
        values,
        accepted_stage_dv_name(step, stage),
        stage_eval.dv.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dv,
        &accepted_velocity_delta_bound(),
        &accepted_stage_name(step, stage, "dv_bound"),
    )?;
    write_value(
        values,
        accepted_stage_name(step, stage, "v_sin"),
        stage_eval.v_sin.clone(),
    );
    write_exact_division_support(
        values,
        accepted_stage_dh_name(step, stage),
        &stage_eval.dh,
        accepted_stage_name(step, stage, "dh_remainder"),
        &stage_eval.dh_remainder,
        accepted_stage_name(step, stage, "dh_slack"),
        &stage_eval.dh_slack,
        &accepted_stage_name(step, stage, "dh"),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dh,
        &accepted_altitude_delta_bound(),
        &accepted_stage_name(step, stage, "dh_bound"),
    )?;
    write_value(
        values,
        accepted_stage_name(step, stage, "v_cos"),
        stage_eval.v_cos.clone(),
    );
    write_exact_division_support(
        values,
        accepted_stage_dx_name(step, stage),
        &stage_eval.dx,
        accepted_stage_name(step, stage, "dx_remainder"),
        &stage_eval.dx_remainder,
        accepted_stage_name(step, stage, "dx_slack"),
        &stage_eval.dx_slack,
        &accepted_stage_name(step, stage, "dx"),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dx,
        &accepted_downrange_delta_bound(),
        &accepted_stage_name(step, stage, "dx_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "lift_over_v"),
        &stage_eval.lift_over_v,
        accepted_stage_name(step, stage, "lift_over_v_remainder"),
        &stage_eval.lift_over_v_remainder,
        accepted_stage_name(step, stage, "lift_over_v_slack"),
        &stage_eval.lift_over_v_slack,
        &accepted_stage_name(step, stage, "lift_over_v"),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "g_cos_gamma"),
        &stage_eval.g_cos_gamma,
        accepted_stage_name(step, stage, "g_cos_gamma_remainder"),
        &stage_eval.g_cos_gamma_remainder,
        accepted_stage_name(step, stage, "g_cos_gamma_slack"),
        &stage_eval.g_cos_gamma_slack,
        &accepted_stage_name(step, stage, "g_cos_gamma"),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "gcos_over_v"),
        &stage_eval.gcos_over_v,
        accepted_stage_name(step, stage, "gcos_over_v_remainder"),
        &stage_eval.gcos_over_v_remainder,
        accepted_stage_name(step, stage, "gcos_over_v_slack"),
        &stage_eval.gcos_over_v_slack,
        &accepted_stage_name(step, stage, "gcos_over_v"),
    );
    write_value(
        values,
        accepted_stage_name(step, stage, "dgamma_accel"),
        stage_eval.dgamma_accel.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dgamma_accel,
        &accepted_gamma_delta_bound(),
        &accepted_stage_name(step, stage, "dgamma_accel_bound"),
    )?;
    write_value(
        values,
        accepted_stage_dgamma_name(step, stage),
        stage_eval.dgamma.clone(),
    );
    write_signed_bound_support(
        values,
        &stage_eval.dgamma,
        &accepted_gamma_delta_bound(),
        &accepted_stage_name(step, stage, "dgamma_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "rho_over_rn"),
        &stage_eval.rho_over_rn_fp,
        accepted_stage_name(step, stage, "rho_over_rn_remainder"),
        &stage_eval.rho_over_rn_remainder,
        accepted_stage_name(step, stage, "rho_over_rn_slack"),
        &stage_eval.rho_over_rn_slack,
        &accepted_stage_name(step, stage, "rho_over_rn"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "rho_over_rn"),
        &stage_eval.rho_over_rn_fp,
        &accepted_rho_over_rn_bound(),
        &accepted_stage_name(step, stage, "rho_over_rn_bound"),
    )?;
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "sqrt_rho_over_rn"),
        &stage_eval.sqrt_rho_over_rn_fp,
        &accepted_sqrt_rho_over_rn_bound(),
        &accepted_stage_name(step, stage, "sqrt_rho_over_rn_sqrt_bound"),
    )?;
    write_value(
        values,
        accepted_stage_name(step, stage, "sqrt_rho_over_rn_remainder"),
        stage_eval.sqrt_rho_over_rn_remainder.clone(),
    );
    write_value(
        values,
        accepted_stage_name(step, stage, "sqrt_rho_over_rn_upper_slack"),
        stage_eval.sqrt_rho_over_rn_upper_slack.clone(),
    );
    write_exact_division_support(
        values,
        accepted_stage_name(step, stage, "heating_factor"),
        &stage_eval.heating_factor,
        accepted_stage_name(step, stage, "heating_factor_remainder"),
        &stage_eval.heating_factor_remainder,
        accepted_stage_name(step, stage, "heating_factor_slack"),
        &stage_eval.heating_factor_slack,
        &accepted_stage_name(step, stage, "heating_factor"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_name(step, stage, "heating_factor"),
        &stage_eval.heating_factor,
        &accepted_heating_factor_bound(),
        &accepted_stage_name(step, stage, "heating_factor_bound"),
    )?;
    write_exact_division_support(
        values,
        accepted_stage_q_dot_name(step, stage),
        &stage_eval.q_dot_i,
        accepted_stage_name(step, stage, "q_dot_remainder"),
        &stage_eval.q_dot_remainder,
        accepted_stage_name(step, stage, "q_dot_slack"),
        &stage_eval.q_dot_slack,
        &accepted_stage_name(step, stage, "q_dot"),
    );
    write_nonnegative_bound_support(
        values,
        accepted_stage_q_dot_name(step, stage),
        &stage_eval.q_dot_i,
        &accepted_q_dot_max_bound(),
        &accepted_stage_name(step, stage, "q_dot_bound"),
    )?;

    let q_ok = write_geq_comparator_support(
        values,
        accepted_stage_q_ok_name(step, stage),
        accepted_stage_name(step, stage, "q_ok_slack"),
        &parameters.q_max,
        &stage_eval.q_i,
        &accepted_positive_comparison_offset(&accepted_q_max_bound()),
        &accepted_stage_name(step, stage, "q_ok"),
    )?;
    let q_dot_ok = write_geq_comparator_support(
        values,
        accepted_stage_q_dot_ok_name(step, stage),
        accepted_stage_name(step, stage, "q_dot_ok_slack"),
        &parameters.q_dot_max,
        &stage_eval.q_dot_i,
        &accepted_positive_comparison_offset(&accepted_q_dot_max_bound()),
        &accepted_stage_name(step, stage, "q_dot_ok"),
    )?;
    let altitude_ok = write_geq_comparator_support(
        values,
        accepted_stage_altitude_ok_name(step, stage),
        accepted_stage_name(step, stage, "altitude_ok_slack"),
        &stage_eval.altitude,
        &parameters.h_min,
        &accepted_positive_comparison_offset(&accepted_altitude_bound()),
        &accepted_stage_name(step, stage, "altitude_ok"),
    )?;
    let velocity_ok = write_geq_comparator_support(
        values,
        accepted_stage_velocity_ok_name(step, stage),
        accepted_stage_name(step, stage, "velocity_ok_slack"),
        &parameters.v_max,
        &stage_eval.velocity,
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "velocity_ok"),
    )?;
    let gamma_lower_ok = write_geq_comparator_support(
        values,
        accepted_stage_gamma_lower_ok_name(step, stage),
        accepted_stage_name(step, stage, "gamma_lower_ok_slack"),
        &stage_eval.gamma,
        &(-parameters.gamma_bound.clone()),
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "gamma_lower_ok"),
    )?;
    let gamma_upper_ok = write_geq_comparator_support(
        values,
        accepted_stage_gamma_upper_ok_name(step, stage),
        accepted_stage_name(step, stage, "gamma_upper_ok_slack"),
        &parameters.gamma_bound,
        &stage_eval.gamma,
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "gamma_upper_ok"),
    )?;
    let gamma_ok = bool_and(gamma_lower_ok, gamma_upper_ok);
    write_bool_value(values, accepted_stage_gamma_ok_name(step, stage), gamma_ok);
    let nominal_q_chain = bool_and(q_ok, q_dot_ok);
    write_bool_value(
        values,
        accepted_stage_name(step, stage, "nominal_q_chain"),
        nominal_q_chain,
    );
    let nominal_state_chain = bool_and(altitude_ok, velocity_ok);
    write_bool_value(
        values,
        accepted_stage_name(step, stage, "nominal_state_chain"),
        nominal_state_chain,
    );
    let nominal_gamma_chain = bool_and(nominal_state_chain, gamma_ok);
    write_bool_value(
        values,
        accepted_stage_name(step, stage, "nominal_gamma_chain"),
        nominal_gamma_chain,
    );
    write_bool_value(
        values,
        accepted_stage_nominal_ok_name(step, stage),
        bool_and(nominal_q_chain, nominal_gamma_chain),
    );

    let abort_velocity_min_ok = write_geq_comparator_support(
        values,
        accepted_stage_abort_velocity_ok_name(step, stage),
        accepted_stage_name(step, stage, "abort_velocity_min_slack"),
        &stage_eval.velocity,
        &stage_eval.abort_selection.velocity_min,
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "abort_velocity_min_ok"),
    )?;
    let abort_velocity_upper_ok_name = accepted_stage_name(step, stage, "abort_velocity_upper_ok");
    let abort_velocity_upper_ok = write_geq_comparator_support(
        values,
        abort_velocity_upper_ok_name.clone(),
        accepted_stage_name(step, stage, "abort_velocity_max_slack"),
        &stage_eval.abort_selection.velocity_max,
        &stage_eval.velocity,
        &accepted_positive_comparison_offset(&accepted_velocity_bound()),
        &accepted_stage_name(step, stage, "abort_velocity_max_ok"),
    )?;
    let abort_velocity_ok = bool_and(abort_velocity_min_ok, abort_velocity_upper_ok);
    write_bool_value(
        values,
        accepted_stage_name(step, stage, "abort_velocity_ok"),
        abort_velocity_ok,
    );
    let abort_gamma_lower_ok = write_geq_comparator_support(
        values,
        accepted_stage_abort_gamma_lower_ok_name(step, stage),
        accepted_stage_name(step, stage, "abort_gamma_lower_slack"),
        &stage_eval.gamma,
        &stage_eval.abort_selection.gamma_min,
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "abort_gamma_lower_ok"),
    )?;
    let abort_gamma_upper_ok = write_geq_comparator_support(
        values,
        accepted_stage_abort_gamma_upper_ok_name(step, stage),
        accepted_stage_name(step, stage, "abort_gamma_upper_slack"),
        &stage_eval.abort_selection.gamma_max,
        &stage_eval.gamma,
        &accepted_signed_comparison_offset(&accepted_gamma_bound()),
        &accepted_stage_name(step, stage, "abort_gamma_upper_ok"),
    )?;
    let abort_gamma_ok = bool_and(abort_gamma_lower_ok, abort_gamma_upper_ok);
    write_bool_value(
        values,
        accepted_stage_abort_gamma_ok_name(step, stage),
        abort_gamma_ok,
    );
    write_bool_value(
        values,
        accepted_stage_abort_ok_name(step, stage),
        bool_and(abort_velocity_ok, abort_gamma_ok),
    );

    let (abort_q_trigger, abort_q_dot_trigger, abort_altitude_floor, abort_velocity_ceiling) =
        abort_thresholds;
    let _ = (
        abort_q_trigger,
        abort_q_dot_trigger,
        abort_altitude_floor,
        abort_velocity_ceiling,
        current_abort_latch,
    );
    Ok(())
}

fn write_accepted_pairwise_max_support(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    target: &str,
    left: &BigInt,
    right: &BigInt,
    bound: &BigInt,
) -> ZkfResult<BigInt> {
    let bit = write_geq_comparator_support(
        values,
        format!("{prefix}_geq_bit"),
        format!("{prefix}_geq_slack"),
        left,
        right,
        &accepted_positive_comparison_offset(bound),
        prefix,
    )?;
    let selected = if bit { left.clone() } else { right.clone() };
    write_nonnegative_bound_support(
        values,
        target.to_string(),
        &selected,
        bound,
        &format!("{prefix}_bound"),
    )?;
    Ok(selected)
}

fn private_reentry_thermal_accepted_witness_inner(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<Witness> {
    let shape = accepted_shape_from_mission_pack(mission_pack)?;
    let parameters = accepted_public_parameters_from_envelope(&mission_pack.public_envelope)?;

    let h0 =
        accepted_parse_decimal_string(altitude_name(), &mission_pack.private.initial_altitude)?;
    let v0 =
        accepted_parse_decimal_string(velocity_name(), &mission_pack.private.initial_velocity)?;
    let gamma0 = accepted_parse_decimal_string(
        gamma_name(),
        &mission_pack.private.initial_flight_path_angle,
    )?;
    let mass =
        accepted_parse_decimal_string(mass_input_name(), &mission_pack.private.vehicle_mass)?;
    let s_ref = accepted_parse_decimal_string(sref_name(), &mission_pack.private.reference_area)?;
    let c_d = accepted_parse_decimal_string(cd_name(), &mission_pack.private.drag_coefficient)?;
    let c_l = accepted_parse_decimal_string(cl_name(), &mission_pack.private.lift_coefficient)?;
    let r_n = accepted_parse_decimal_string(rn_name(), &mission_pack.private.nose_radius)?;

    let abort_q_trigger = accepted_parse_decimal_string(
        accepted_abort_q_trigger_name(),
        &mission_pack.private.abort_thresholds.q_trigger_min,
    )?;
    let abort_q_dot_trigger = accepted_parse_decimal_string(
        accepted_abort_q_dot_trigger_name(),
        &mission_pack.private.abort_thresholds.q_dot_trigger_min,
    )?;
    let abort_altitude_floor = accepted_parse_decimal_string(
        accepted_abort_altitude_floor_name(),
        &mission_pack.private.abort_thresholds.altitude_floor,
    )?;
    let abort_velocity_ceiling = accepted_parse_decimal_string(
        accepted_abort_velocity_ceiling_name(),
        &mission_pack.private.abort_thresholds.velocity_ceiling,
    )?;

    let bank_cosines = mission_pack
        .private
        .bank_angle_cosines
        .iter()
        .enumerate()
        .map(|(step, value)| accepted_parse_decimal_string(&bank_cos_name(step), value))
        .collect::<ZkfResult<Vec<_>>>()?;

    let mut step_evaluations = Vec::with_capacity(shape.steps);
    let mut altitudes = vec![h0.clone()];
    let mut downranges = vec![zero()];
    let mut velocities = vec![v0.clone()];
    let mut gammas = vec![gamma0.clone()];
    let mut heats = vec![zero()];
    let mut abort_latches = vec![false];

    for step in 0..shape.steps {
        let evaluation = accepted_step_evaluation(
            &altitudes[step],
            &downranges[step],
            &velocities[step],
            &gammas[step],
            &heats[step],
            abort_latches[step],
            &bank_cosines[step],
            mission_pack,
            &parameters,
        )?;
        altitudes.push(evaluation.next_altitude.clone());
        downranges.push(evaluation.next_downrange.clone());
        velocities.push(evaluation.next_velocity.clone());
        gammas.push(evaluation.next_gamma.clone());
        heats.push(evaluation.next_heat.clone());
        abort_latches.push(evaluation.next_abort_latch);
        step_evaluations.push(evaluation);
    }

    let mut values = BTreeMap::new();

    for (signal, value, bound, prefix, nonzero_prefix) in [
        (
            q_max_name(),
            &parameters.q_max,
            accepted_q_max_bound(),
            "accepted_q_max",
            Some(format!("{}_accepted_nonzero", q_max_name())),
        ),
        (
            q_dot_max_name(),
            &parameters.q_dot_max,
            accepted_q_dot_max_bound(),
            "accepted_q_dot_max",
            Some(format!("{}_accepted_nonzero", q_dot_max_name())),
        ),
        (
            h_min_name(),
            &parameters.h_min,
            accepted_altitude_bound(),
            "accepted_h_min",
            None,
        ),
        (
            v_max_name(),
            &parameters.v_max,
            accepted_velocity_bound(),
            "accepted_v_max",
            Some(format!("{}_accepted_nonzero", v_max_name())),
        ),
        (
            gamma_bound_name(),
            &parameters.gamma_bound,
            accepted_gamma_bound(),
            "accepted_gamma_bound",
            Some(format!("{}_accepted_nonzero", gamma_bound_name())),
        ),
        (
            gravity_name(),
            &parameters.g_0,
            accepted_gravity_bound(),
            "accepted_g0",
            Some(format!("{}_accepted_nonzero", gravity_name())),
        ),
        (
            k_sg_name(),
            &parameters.k_sg,
            accepted_k_sg_bound(),
            "accepted_k_sg",
            Some(format!("{}_accepted_nonzero", k_sg_name())),
        ),
    ] {
        write_nonnegative_bound_support(&mut values, signal.to_string(), value, &bound, prefix)?;
        if let Some(prefix) = nonzero_prefix {
            write_nonzero_inverse_support(&mut values, value, &prefix)?;
        }
    }

    write_nonnegative_bound_support(
        &mut values,
        altitude_name().to_string(),
        &h0,
        &accepted_altitude_bound(),
        "accepted_h0",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        velocity_name().to_string(),
        &v0,
        &accepted_velocity_bound(),
        "accepted_v0",
    )?;
    write_nonzero_inverse_support(&mut values, &v0, "accepted_v0_nonzero")?;
    write_value(&mut values, gamma_name().to_string(), gamma0.clone());
    write_signed_bound_support(
        &mut values,
        &gamma0,
        &accepted_gamma_bound(),
        "accepted_gamma0",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        mass_input_name().to_string(),
        &mass,
        &accepted_mass_bound(),
        "accepted_mass",
    )?;
    write_nonzero_inverse_support(&mut values, &mass, "accepted_mass_nonzero")?;
    write_nonnegative_bound_support(
        &mut values,
        sref_name().to_string(),
        &s_ref,
        &accepted_area_bound(),
        "accepted_sref",
    )?;
    write_nonzero_inverse_support(&mut values, &s_ref, "accepted_sref_nonzero")?;
    write_nonnegative_bound_support(
        &mut values,
        cd_name().to_string(),
        &c_d,
        &accepted_coeff_bound(),
        "accepted_cd",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        cl_name().to_string(),
        &c_l,
        &accepted_coeff_bound(),
        "accepted_cl",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        rn_name().to_string(),
        &r_n,
        &accepted_nose_radius_bound(),
        "accepted_rn",
    )?;
    write_nonzero_inverse_support(&mut values, &r_n, "accepted_rn_nonzero")?;

    for (step, bank_cos) in bank_cosines.iter().enumerate() {
        write_value(&mut values, bank_cos_name(step), bank_cos.clone());
        write_signed_bound_support(
            &mut values,
            bank_cos,
            &accepted_bank_cos_bound(),
            &format!("accepted_step_{step}_bank_cos"),
        )?;
    }

    for row in 0..shape.atmosphere_rows {
        let names = accepted_atmosphere_row_input_names(row);
        let band = &mission_pack.private.atmosphere_bands[row];
        let start = accepted_parse_decimal_string(&names[0], &band.altitude_start)?;
        let end = accepted_parse_decimal_string(&names[1], &band.altitude_end)?;
        let density_start = accepted_parse_decimal_string(&names[2], &band.density_start)?;
        let density_end = accepted_parse_decimal_string(&names[3], &band.density_end)?;
        write_nonnegative_bound_support(
            &mut values,
            names[0].clone(),
            &start,
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_start"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[1].clone(),
            &end,
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_end"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[2].clone(),
            &density_start,
            &accepted_density_bound(),
            &format!("accepted_atmosphere_row_{row}_density_start"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[3].clone(),
            &density_end,
            &accepted_density_bound(),
            &format!("accepted_atmosphere_row_{row}_density_end"),
        )?;
        let span = &end - &start;
        write_nonnegative_bound_support(
            &mut values,
            format!("accepted_atmosphere_row_{row}_span"),
            &span,
            &accepted_altitude_bound(),
            &format!("accepted_atmosphere_row_{row}_span"),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &span,
            &format!("accepted_atmosphere_row_{row}_span"),
        )?;
        if row + 1 < shape.atmosphere_rows {
            let next_start = accepted_parse_decimal_string(
                &accepted_atmosphere_altitude_start_name(row + 1),
                &mission_pack.private.atmosphere_bands[row + 1].altitude_start,
            )?;
            let order = next_start - &end;
            write_nonnegative_bound_support(
                &mut values,
                format!("accepted_atmosphere_row_{row}_order"),
                &order,
                &accepted_altitude_bound(),
                &format!("accepted_atmosphere_row_{row}_order"),
            )?;
        }
    }

    for row in 0..shape.sine_rows {
        let names = accepted_sine_row_input_names(row);
        let band = &mission_pack.private.sine_bands[row];
        let start = accepted_parse_decimal_string(&names[0], &band.gamma_start)?;
        let end = accepted_parse_decimal_string(&names[1], &band.gamma_end)?;
        let value_start = accepted_parse_decimal_string(&names[2], &band.sine_start)?;
        let value_end = accepted_parse_decimal_string(&names[3], &band.sine_end)?;
        write_value(&mut values, names[0].clone(), start.clone());
        write_signed_bound_support(
            &mut values,
            &start,
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_start"),
        )?;
        write_value(&mut values, names[1].clone(), end.clone());
        write_signed_bound_support(
            &mut values,
            &end,
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_end"),
        )?;
        write_value(&mut values, names[2].clone(), value_start.clone());
        write_signed_bound_support(
            &mut values,
            &value_start,
            &accepted_trig_bound(),
            &format!("accepted_sine_row_{row}_value_start"),
        )?;
        write_value(&mut values, names[3].clone(), value_end.clone());
        write_signed_bound_support(
            &mut values,
            &value_end,
            &accepted_trig_bound(),
            &format!("accepted_sine_row_{row}_value_end"),
        )?;
        let span = &end - &start;
        write_nonnegative_bound_support(
            &mut values,
            format!("accepted_sine_row_{row}_span"),
            &span,
            &accepted_gamma_bound(),
            &format!("accepted_sine_row_{row}_span"),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &span,
            &format!("accepted_sine_row_{row}_span"),
        )?;
        if row + 1 < shape.sine_rows {
            let next_start = accepted_parse_decimal_string(
                &accepted_sine_gamma_start_name(row + 1),
                &mission_pack.private.sine_bands[row + 1].gamma_start,
            )?;
            let order = next_start - &end;
            write_nonnegative_bound_support(
                &mut values,
                format!("accepted_sine_row_{row}_order"),
                &order,
                &accepted_gamma_bound(),
                &format!("accepted_sine_row_{row}_order"),
            )?;
        }
    }

    for row in 0..shape.abort_rows {
        let names = accepted_abort_row_input_names(row);
        let band = &mission_pack.private.abort_corridor_bands[row];
        let altitude_start = accepted_parse_decimal_string(&names[0], &band.altitude_start)?;
        let altitude_end = accepted_parse_decimal_string(&names[1], &band.altitude_end)?;
        let velocity_min = accepted_parse_decimal_string(&names[2], &band.velocity_min)?;
        let velocity_max = accepted_parse_decimal_string(&names[3], &band.velocity_max)?;
        let gamma_min = accepted_parse_decimal_string(&names[4], &band.gamma_min)?;
        let gamma_max = accepted_parse_decimal_string(&names[5], &band.gamma_max)?;
        write_nonnegative_bound_support(
            &mut values,
            names[0].clone(),
            &altitude_start,
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_altitude_start"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[1].clone(),
            &altitude_end,
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_altitude_end"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[2].clone(),
            &velocity_min,
            &accepted_velocity_bound(),
            &format!("accepted_abort_row_{row}_velocity_min"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            names[3].clone(),
            &velocity_max,
            &accepted_velocity_bound(),
            &format!("accepted_abort_row_{row}_velocity_max"),
        )?;
        write_value(&mut values, names[4].clone(), gamma_min.clone());
        write_signed_bound_support(
            &mut values,
            &gamma_min,
            &accepted_gamma_bound(),
            &format!("accepted_abort_row_{row}_gamma_min"),
        )?;
        write_value(&mut values, names[5].clone(), gamma_max.clone());
        write_signed_bound_support(
            &mut values,
            &gamma_max,
            &accepted_gamma_bound(),
            &format!("accepted_abort_row_{row}_gamma_max"),
        )?;
        let span = &altitude_end - &altitude_start;
        write_nonnegative_bound_support(
            &mut values,
            format!("accepted_abort_row_{row}_span"),
            &span,
            &accepted_altitude_bound(),
            &format!("accepted_abort_row_{row}_span"),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &span,
            &format!("accepted_abort_row_{row}_span"),
        )?;
        if row + 1 < shape.abort_rows {
            let next_start = accepted_parse_decimal_string(
                &accepted_abort_altitude_start_name(row + 1),
                &mission_pack.private.abort_corridor_bands[row + 1].altitude_start,
            )?;
            let order = next_start - &altitude_end;
            write_nonnegative_bound_support(
                &mut values,
                format!("accepted_abort_row_{row}_order"),
                &order,
                &accepted_altitude_bound(),
                &format!("accepted_abort_row_{row}_order"),
            )?;
        }
    }

    write_nonnegative_bound_support(
        &mut values,
        accepted_abort_q_trigger_name().to_string(),
        &abort_q_trigger,
        &accepted_q_max_bound(),
        "accepted_abort_q_trigger",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        accepted_abort_q_dot_trigger_name().to_string(),
        &abort_q_dot_trigger,
        &accepted_q_dot_max_bound(),
        "accepted_abort_q_dot_trigger",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        accepted_abort_altitude_floor_name().to_string(),
        &abort_altitude_floor,
        &accepted_altitude_bound(),
        "accepted_abort_altitude_floor",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        accepted_abort_velocity_ceiling_name().to_string(),
        &abort_velocity_ceiling,
        &accepted_velocity_bound(),
        "accepted_abort_velocity_ceiling",
    )?;
    write_nonzero_inverse_support(
        &mut values,
        &abort_velocity_ceiling,
        "accepted_abort_velocity_ceiling_nonzero",
    )?;

    for step in 0..shape.steps {
        let evaluation = &step_evaluations[step];

        for (stage, source_stage) in [(2usize, 1usize), (3usize, 2usize)] {
            let source = &evaluation.stages[source_stage - 1];
            for (suffix, derivative) in [
                ("h_half", &source.dh),
                ("x_half", &source.dx),
                ("v_half", &source.dv),
                ("gamma_half", &source.dgamma),
                ("heat_half", &source.q_dot_i),
            ] {
                let (half, remainder, slack) = euclidean_division(derivative, &two())?;
                write_exact_division_support(
                    &mut values,
                    accepted_stage_name(step, stage, suffix),
                    &half,
                    accepted_stage_name(step, stage, &format!("{suffix}_remainder")),
                    &remainder,
                    accepted_stage_name(step, stage, &format!("{suffix}_slack")),
                    &slack,
                    &accepted_stage_name(step, stage, suffix),
                );
            }
        }

        for stage in 1..=4 {
            write_accepted_stage_support(
                &mut values,
                step,
                stage,
                &evaluation.stages[stage - 1],
                abort_latches[step],
                &shape,
                &parameters,
                (
                    &abort_q_trigger,
                    &abort_q_dot_trigger,
                    &abort_altitude_floor,
                    &abort_velocity_ceiling,
                ),
            )?;
        }

        for (label, quotient, remainder, slack) in [
            (
                "dh",
                &evaluation.weighted_dh,
                &evaluation.weighted_dh_remainder,
                &evaluation.weighted_dh_slack,
            ),
            (
                "dx",
                &evaluation.weighted_dx,
                &evaluation.weighted_dx_remainder,
                &evaluation.weighted_dx_slack,
            ),
            (
                "dv",
                &evaluation.weighted_dv,
                &evaluation.weighted_dv_remainder,
                &evaluation.weighted_dv_slack,
            ),
            (
                "dgamma",
                &evaluation.weighted_dgamma,
                &evaluation.weighted_dgamma_remainder,
                &evaluation.weighted_dgamma_slack,
            ),
            (
                "dheat",
                &evaluation.weighted_dheat,
                &evaluation.weighted_dheat_remainder,
                &evaluation.weighted_dheat_slack,
            ),
        ] {
            write_exact_division_support(
                &mut values,
                accepted_weighted_delta_name(step, label),
                quotient,
                accepted_stage_name(step, 0, &format!("weighted_{label}_remainder")),
                remainder,
                accepted_stage_name(step, 0, &format!("weighted_{label}_slack")),
                slack,
                &accepted_stage_name(step, 0, &format!("weighted_{label}")),
            );
            values.insert(
                nonlinear_anchor_name(&accepted_weighted_delta_name(step, label)),
                field_square(quotient),
            );
        }

        write_nonnegative_bound_support(
            &mut values,
            h_state_name(step + 1),
            &evaluation.next_altitude,
            &accepted_altitude_bound(),
            &format!("accepted_state_{}_h", step + 1),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            accepted_downrange_state_name(step + 1),
            &evaluation.next_downrange,
            &accepted_downrange_bound(),
            &format!("accepted_state_{}_x", step + 1),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            v_state_name(step + 1),
            &evaluation.next_velocity,
            &accepted_velocity_bound(),
            &format!("accepted_state_{}_v", step + 1),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &evaluation.next_velocity,
            &format!("accepted_state_{}_v_nonzero", step + 1),
        )?;
        write_value(
            &mut values,
            gamma_state_name(step + 1),
            evaluation.next_gamma.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &evaluation.next_gamma,
            &accepted_gamma_bound(),
            &format!("accepted_state_{}_gamma", step + 1),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            accepted_heat_state_name(step + 1),
            &evaluation.next_heat,
            &accepted_heat_bound(),
            &format!("accepted_state_{}_heat", step + 1),
        )?;
        write_bool_value(
            &mut values,
            accepted_abort_latch_state_name(step + 1),
            evaluation.next_abort_latch,
        );

        let q_predicate_bits = (1..=4)
            .map(|stage| {
                write_geq_comparator_support(
                    &mut values,
                    accepted_stage_name(step, stage, "abort_q_predicate"),
                    accepted_stage_name(step, stage, "abort_q_predicate_slack"),
                    &evaluation.stages[stage - 1].q_i,
                    &abort_q_trigger,
                    &accepted_positive_comparison_offset(&accepted_q_max_bound()),
                    &accepted_stage_name(step, stage, "abort_q_predicate"),
                )
            })
            .collect::<ZkfResult<Vec<_>>>()?;
        let q_abort_chain = bool_or(q_predicate_bits[0], q_predicate_bits[1]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_q_chain"),
            q_abort_chain,
        );
        let q_abort_chain_2 = bool_or(q_abort_chain, q_predicate_bits[2]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_q_chain_2"),
            q_abort_chain_2,
        );
        write_bool_value(
            &mut values,
            accepted_q_abort_predicate_name(step),
            evaluation.q_abort_predicate,
        );

        let q_dot_predicate_bits = (1..=4)
            .map(|stage| {
                write_geq_comparator_support(
                    &mut values,
                    accepted_stage_name(step, stage, "abort_q_dot_predicate"),
                    accepted_stage_name(step, stage, "abort_q_dot_predicate_slack"),
                    &evaluation.stages[stage - 1].q_dot_i,
                    &abort_q_dot_trigger,
                    &accepted_positive_comparison_offset(&accepted_q_dot_max_bound()),
                    &accepted_stage_name(step, stage, "abort_q_dot_predicate"),
                )
            })
            .collect::<ZkfResult<Vec<_>>>()?;
        let q_dot_abort_chain = bool_or(q_dot_predicate_bits[0], q_dot_predicate_bits[1]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_q_dot_chain"),
            q_dot_abort_chain,
        );
        let q_dot_abort_chain_2 = bool_or(q_dot_abort_chain, q_dot_predicate_bits[2]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_q_dot_chain_2"),
            q_dot_abort_chain_2,
        );
        write_bool_value(
            &mut values,
            accepted_q_dot_abort_predicate_name(step),
            evaluation.q_dot_abort_predicate,
        );

        write_geq_comparator_support(
            &mut values,
            accepted_altitude_abort_predicate_name(step),
            accepted_stage_name(step, 0, "abort_altitude_slack"),
            &abort_altitude_floor,
            &evaluation.next_altitude,
            &accepted_positive_comparison_offset(&accepted_altitude_bound()),
            &accepted_stage_name(step, 0, "abort_altitude"),
        )?;
        write_geq_comparator_support(
            &mut values,
            accepted_velocity_abort_predicate_name(step),
            accepted_stage_name(step, 0, "abort_velocity_slack"),
            &evaluation.next_velocity,
            &abort_velocity_ceiling,
            &accepted_positive_comparison_offset(&accepted_velocity_bound()),
            &accepted_stage_name(step, 0, "abort_velocity"),
        )?;

        let trigger_chain = bool_or(
            evaluation.q_abort_predicate,
            evaluation.q_dot_abort_predicate,
        );
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "trigger_chain"),
            trigger_chain,
        );
        let trigger_chain_2 = bool_or(trigger_chain, evaluation.altitude_abort_predicate);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "trigger_chain_2"),
            trigger_chain_2,
        );
        write_bool_value(&mut values, accepted_trigger_name(step), evaluation.trigger);

        let nominal_stage_bits = (1..=4)
            .map(|stage| accepted_stage_nominal_ok(&evaluation.stages[stage - 1], &parameters))
            .collect::<Vec<_>>();
        let nominal_chain = bool_and(nominal_stage_bits[0], nominal_stage_bits[1]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "nominal_chain"),
            nominal_chain,
        );
        let nominal_chain_2 = bool_and(nominal_chain, nominal_stage_bits[2]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "nominal_chain_2"),
            nominal_chain_2,
        );
        write_bool_value(
            &mut values,
            accepted_nominal_ok_name(step),
            evaluation.nominal_ok,
        );

        let abort_stage_bits = (1..=4)
            .map(|stage| accepted_stage_abort_ok(&evaluation.stages[stage - 1]))
            .collect::<Vec<_>>();
        let abort_chain = bool_and(abort_stage_bits[0], abort_stage_bits[1]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_chain"),
            abort_chain,
        );
        let abort_chain_2 = bool_and(abort_chain, abort_stage_bits[2]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "abort_chain_2"),
            abort_chain_2,
        );
        write_bool_value(
            &mut values,
            accepted_abort_ok_name(step),
            evaluation.abort_ok,
        );

        let not_current_abort = bool_not(abort_latches[step]);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "not_current_abort"),
            not_current_abort,
        );
        write_bool_value(
            &mut values,
            accepted_first_trigger_name(step),
            evaluation.first_trigger,
        );
        let nominal_or_trigger = bool_or(evaluation.nominal_ok, evaluation.trigger);
        write_bool_value(
            &mut values,
            accepted_stage_name(step, 0, "nominal_or_trigger"),
            nominal_or_trigger,
        );
        write_bool_value(
            &mut values,
            accepted_step_valid_name(step),
            evaluation.step_valid,
        );
    }

    let mut q_candidates = Vec::with_capacity(shape.steps * 4);
    let mut q_dot_candidates = Vec::with_capacity(shape.steps * 4);
    for evaluation in &step_evaluations {
        for stage in &evaluation.stages {
            q_candidates.push(stage.q_i.clone());
            q_dot_candidates.push(stage.q_dot_i.clone());
        }
    }

    let mut current_q_max = q_candidates[0].clone();
    for (index, candidate) in q_candidates.iter().enumerate().skip(1) {
        current_q_max = write_accepted_pairwise_max_support(
            &mut values,
            &format!("accepted_peak_q_running_{index}"),
            &format!("accepted_peak_q_running_{index}"),
            &current_q_max,
            candidate,
            &accepted_dynamic_pressure_bound(),
        )?;
    }
    write_value(&mut values, peak_q_output_name(), current_q_max.clone());

    let mut current_q_dot_max = q_dot_candidates[0].clone();
    for (index, candidate) in q_dot_candidates.iter().enumerate().skip(1) {
        current_q_dot_max = write_accepted_pairwise_max_support(
            &mut values,
            &format!("accepted_peak_q_dot_running_{index}"),
            &format!("accepted_peak_q_dot_running_{index}"),
            &current_q_dot_max,
            candidate,
            &accepted_q_dot_max_bound(),
        )?;
    }
    write_value(
        &mut values,
        peak_q_dot_output_name(),
        current_q_dot_max.clone(),
    );

    let mut previous_digest = field_ref(&trajectory_seed_tag());
    for step in 0..=shape.steps {
        let boundary_hi = write_hash_lanes(
            &mut values,
            &format!("accepted_boundary_hi_{step}"),
            poseidon_permutation4_reentry([
                &altitudes[step],
                &downranges[step],
                &velocities[step],
                &gammas[step],
            ])?,
        );
        let boundary_lo = write_hash_lanes(
            &mut values,
            &format!("accepted_boundary_lo_{step}"),
            poseidon_permutation4_reentry([
                &heats[step],
                &(if abort_latches[step] { one() } else { zero() }),
                &BigInt::from(step as u64),
                &zero(),
            ])?,
        );
        let boundary_hi_bigint = boundary_hi.as_bigint();
        let boundary_lo_bigint = boundary_lo.as_bigint();
        let step_tag = trajectory_step_tag(step);
        let zero_lane = zero();
        let state_digest = write_hash_lanes(
            &mut values,
            &format!("accepted_boundary_state_{step}"),
            poseidon_permutation4_reentry([
                &boundary_hi_bigint,
                &boundary_lo_bigint,
                &step_tag,
                &zero_lane,
            ])?,
        );
        let previous_digest_bigint = previous_digest.as_bigint();
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("accepted_boundary_chain_{step}"),
            poseidon_permutation4_reentry([
                &state_digest.as_bigint(),
                &previous_digest_bigint,
                &step_tag,
                &one(),
            ])?,
        );
    }
    values.insert(
        trajectory_commitment_output_name().to_string(),
        previous_digest,
    );

    let terminal_hi = write_hash_lanes(
        &mut values,
        "accepted_terminal_state_hi",
        poseidon_permutation4_reentry([
            &altitudes[shape.steps],
            &downranges[shape.steps],
            &velocities[shape.steps],
            &gammas[shape.steps],
        ])?,
    );
    let terminal_lo = write_hash_lanes(
        &mut values,
        "accepted_terminal_state_lo",
        poseidon_permutation4_reentry([
            &heats[shape.steps],
            &(if abort_latches[shape.steps] {
                one()
            } else {
                zero()
            }),
            &BigInt::from(shape.steps as u64),
            &terminal_state_tag(),
        ])?,
    );
    let terminal_hi_bigint = terminal_hi.as_bigint();
    let terminal_lo_bigint = terminal_lo.as_bigint();
    let terminal_tag = terminal_state_tag();
    let terminal_digest = write_hash_lanes(
        &mut values,
        "accepted_terminal_state_commitment",
        poseidon_permutation4_reentry([
            &terminal_hi_bigint,
            &terminal_lo_bigint,
            &terminal_tag,
            &zero(),
        ])?,
    );
    values.insert(
        terminal_state_commitment_output_name().to_string(),
        terminal_digest,
    );
    values.insert(
        constraint_satisfaction_output_name().to_string(),
        FieldElement::ONE,
    );

    Ok(Witness { values })
}

pub fn private_reentry_thermal_accepted_witness_from_mission_pack(
    mission_pack: &ReentryMissionPackV2,
) -> ZkfResult<Witness> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_reentry_thermal_accepted_witness_inner(mission_pack)
    })
}

pub fn reentry_mission_pack_v2_sample_with_steps(steps: usize) -> ZkfResult<ReentryMissionPackV2> {
    let request = private_reentry_thermal_sample_request_with_steps(steps)?;
    let atmosphere_breakpoints = [
        decimal_scaled("0"),
        decimal_scaled("20"),
        decimal_scaled("40"),
        decimal_scaled("60"),
        decimal_scaled("80"),
        decimal_scaled("120"),
    ];
    let gamma_breakpoints = [
        decimal_scaled("-0.35"),
        decimal_scaled("-0.15"),
        decimal_scaled("0"),
        decimal_scaled("0.15"),
        decimal_scaled("0.35"),
    ];

    let atmosphere_bands = atmosphere_breakpoints
        .windows(2)
        .map(|window| ReentryAtmosphereBandRowV1 {
            altitude_start: scaled_bigint_to_decimal_string(&window[0]),
            altitude_end: scaled_bigint_to_decimal_string(&window[1]),
            density_start: scaled_bigint_to_decimal_string(&sample_density_from_altitude(
                &window[0],
            )),
            density_end: scaled_bigint_to_decimal_string(&sample_density_from_altitude(&window[1])),
        })
        .collect::<Vec<_>>();
    let sine_bands = gamma_breakpoints
        .windows(2)
        .map(|window| ReentrySineBandRowV1 {
            gamma_start: scaled_bigint_to_decimal_string(&window[0]),
            gamma_end: scaled_bigint_to_decimal_string(&window[1]),
            sine_start: scaled_bigint_to_decimal_string(&sample_sine_from_gamma(&window[0])),
            sine_end: scaled_bigint_to_decimal_string(&sample_sine_from_gamma(&window[1])),
        })
        .collect::<Vec<_>>();

    Ok(ReentryMissionPackV2 {
        private: ReentryPrivateInputsV2 {
            initial_altitude: request.private.initial_altitude,
            initial_velocity: request.private.initial_velocity,
            initial_flight_path_angle: request.private.initial_flight_path_angle,
            vehicle_mass: request.private.vehicle_mass,
            reference_area: request.private.reference_area,
            drag_coefficient: request.private.drag_coefficient,
            lift_coefficient: request.private.lift_coefficient,
            nose_radius: request.private.nose_radius,
            bank_angle_cosines: request.private.bank_angle_cosines,
            atmosphere_bands,
            sine_bands,
            abort_thresholds: ReentryAbortThresholdsV1 {
                q_trigger_min: scaled_bigint_to_decimal_string(
                    &(sample_public_parameters().q_max + decimal_scaled("5")),
                ),
                q_dot_trigger_min: scaled_bigint_to_decimal_string(
                    &(sample_public_parameters().q_dot_max + decimal_scaled("5")),
                ),
                altitude_floor: "10".to_string(),
                velocity_ceiling: "8".to_string(),
            },
            abort_corridor_bands: vec![ReentryAbortCorridorBandRowV1 {
                altitude_start: "0".to_string(),
                altitude_end: "120".to_string(),
                velocity_min: "0".to_string(),
                velocity_max: "8".to_string(),
                gamma_min: "-0.35".to_string(),
                gamma_max: "0.35".to_string(),
            }],
        },
        public_envelope: request.public.into(),
        private_model_commitments: ReentryPrivateModelCommitmentsV1 {
            mission_id: format!("sample-reentry-v2-{steps}-step"),
            aerodynamic_model_commitment: "sample-aero-commitment".to_string(),
            thermal_model_commitment: "sample-thermal-commitment".to_string(),
            guidance_policy_commitment: "sample-guidance-commitment".to_string(),
        },
        provenance_metadata: BTreeMap::from([
            ("sample_profile".to_string(), "reentry-v2".to_string()),
            (
                "materialization_surface".to_string(),
                "state-derived-atmosphere-and-sine-bands".to_string(),
            ),
        ]),
    })
}

pub fn build_reentry_assurance_receipt(
    mission_pack: &ReentryMissionPackV1,
    witness: &Witness,
    backend: &str,
) -> ZkfResult<ReentryAssuranceReceiptV1> {
    let read_output = |name: &str| -> ZkfResult<String> {
        witness
            .values
            .get(name)
            .map(|value| scaled_bigint_to_decimal_string(&value.as_bigint()))
            .ok_or_else(|| ZkfError::MissingWitnessValue {
                signal: name.to_string(),
            })
    };

    Ok(ReentryAssuranceReceiptV1 {
        mission_id: mission_pack.private_model_commitments.mission_id.clone(),
        mission_pack_digest: super::science::sha256_hex_json("reentry-mission-pack-v1", mission_pack)?,
        backend: backend.to_string(),
        theorem_lane: "transparent-fixed-policy-cpu".to_string(),
        mathematical_model:
            "fixed-horizon reduced-order explicit-Euler reentry certificate over committed private mission-pack parameters"
                .to_string(),
        theorem_hypotheses: vec![
            "plonky3-transparent-proof-semantics".to_string(),
            "poseidon-width4-native-permutation-surface".to_string(),
            "mission-pack-provenance-is-authentic".to_string(),
        ],
        horizon_steps: mission_pack.public_envelope.certified_horizon_steps,
        fixed_point_scale: fixed_scale().to_str_radix(10),
        trajectory_commitment: read_output(trajectory_commitment_output_name())?,
        terminal_state_commitment: read_output(terminal_state_commitment_output_name())?,
        peak_dynamic_pressure: read_output(peak_q_output_name())?,
        peak_heating_rate: read_output(peak_q_dot_output_name())?,
        compliance_bit: witness
            .values
            .get(constraint_satisfaction_output_name())
            .map(|value| value == &FieldElement::ONE)
            .unwrap_or(false),
        minimal_tcb: vec![
            "rust-toolchain".to_string(),
            "zkf-backends/plonky3".to_string(),
            "proof-libraries".to_string(),
            "host-os-and-hardware".to_string(),
            "mission-pack-authenticity".to_string(),
        ],
    })
}

pub fn build_reentry_assurance_receipt_v2(
    signed_pack: &SignedReentryMissionPackV1,
    signer_manifest: &ReentrySignerManifestV1,
    witness: &Witness,
    backend: &str,
) -> ZkfResult<ReentryAssuranceReceiptV2> {
    let read_output = |name: &str| -> ZkfResult<String> {
        witness
            .values
            .get(name)
            .map(|value| accepted_scaled_bigint_to_decimal_string(&value.as_bigint()))
            .ok_or_else(|| ZkfError::MissingWitnessValue {
                signal: name.to_string(),
            })
    };

    Ok(ReentryAssuranceReceiptV2 {
        mission_id: signed_pack
            .payload
            .private_model_commitments
            .mission_id
            .clone(),
        mission_pack_digest: signed_pack.payload_digest.clone(),
        signer_manifest_digest: reentry_signer_manifest_digest(signer_manifest)?,
        signer_identity: signed_pack.signer_identity.clone(),
        backend: backend.to_string(),
        theorem_lane: "transparent-fixed-policy-cpu".to_string(),
        model_revision: "reentry-mission-pack-v2-rk4-private-table-abort".to_string(),
        mathematical_model: "fixed-horizon reduced-order RK4 reentry certificate with private atmosphere/sine band interpolation, in-circuit cosine closure, full-state Poseidon commitments, and mechanized nominal-or-valid-abort semantics"
            .to_string(),
        theorem_hypotheses: vec![
            "plonky3-transparent-proof-semantics".to_string(),
            "hybrid-ed25519-ml-dsa44-signature-libraries".to_string(),
            "mission-pack-provenance-is-authentic".to_string(),
        ],
        horizon_steps: signed_pack.payload.public_envelope.certified_horizon_steps,
        fixed_point_scale: accepted_scale().to_str_radix(10),
        trajectory_commitment: read_output(trajectory_commitment_output_name())?,
        terminal_state_commitment: read_output(terminal_state_commitment_output_name())?,
        peak_dynamic_pressure: read_output(peak_q_output_name())?,
        peak_heating_rate: read_output(peak_q_dot_output_name())?,
        compliance_bit: witness
            .values
            .get(constraint_satisfaction_output_name())
            .map(|value| value == &FieldElement::ONE)
            .unwrap_or(false),
        minimal_tcb: vec![
            "rust-toolchain".to_string(),
            "zkf-backends/plonky3".to_string(),
            "proof-libraries".to_string(),
            "host-os-and-hardware".to_string(),
            "signature-libraries".to_string(),
            "signed-mission-pack-authority".to_string(),
        ],
    })
}

// ---------------------------------------------------------------------------
// Circuit builder
// ---------------------------------------------------------------------------

fn private_reentry_thermal_showcase_inner(steps: usize) -> ZkfResult<TemplateProgram> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private reentry thermal showcase requires at least one integration step".to_string(),
        ));
    }

    let mut builder = ProgramBuilder::new(
        format!("private_reentry_thermal_showcase_{steps}_step"),
        REENTRY_APP_FIELD,
    );
    builder.metadata_entry("application", "private-reentry-mission-assurance")?;
    builder.metadata_entry("integration_steps", steps.to_string())?;
    builder.metadata_entry("integrator", "euler")?;
    builder.metadata_entry("time_step_seconds", "1")?;
    builder.metadata_entry("fixed_point_scale", fixed_scale().to_str_radix(10))?;
    builder.metadata_entry("units", "kilometers, kilometers_per_second, seconds")?;
    builder.metadata_entry("accepted_backend", "plonky3")?;
    builder.metadata_entry("theorem_lane", "transparent-fixed-policy-cpu")?;
    builder.metadata_entry(
        "safe_certificate_semantics",
        "constraint_satisfaction is fixed to 1 for accepted reentry trajectories; invalid trajectories fail closed during witness generation",
    )?;
    builder.metadata_entry("altitude_bound_scaled", altitude_bound().to_str_radix(10))?;
    builder.metadata_entry(
        "velocity_bound_scaled",
        velocity_bound_value().to_str_radix(10),
    )?;
    builder.metadata_entry("mass_bound_scaled", mass_bound_value().to_str_radix(10))?;
    builder.metadata_entry(
        "stack_grow_strategy",
        "stacker::maybe_grow used for template build and witness generation",
    )?;

    let mut expected_inputs = Vec::with_capacity(
        PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS + private_input_count_for_steps(steps),
    );
    let public_outputs = vec![
        trajectory_commitment_output_name().to_string(),
        terminal_state_commitment_output_name().to_string(),
        constraint_satisfaction_output_name().to_string(),
        peak_q_output_name().to_string(),
        peak_q_dot_output_name().to_string(),
    ];

    // -----------------------------------------------------------------------
    // Public inputs
    // -----------------------------------------------------------------------
    for public_name in [
        q_max_name(),
        q_dot_max_name(),
        h_min_name(),
        v_max_name(),
        gamma_bound_name(),
        gravity_name(),
        k_sg_name(),
    ] {
        builder.public_input(public_name)?;
        expected_inputs.push(public_name.to_string());
    }

    // Bound-check public inputs
    append_nonnegative_bound(&mut builder, q_max_name(), &q_max_bound(), "q_max_bound")?;
    append_nonnegative_bound(
        &mut builder,
        q_dot_max_name(),
        &q_dot_max_bound(),
        "q_dot_max_bound",
    )?;
    append_nonnegative_bound(&mut builder, h_min_name(), &altitude_bound(), "h_min_bound")?;
    append_nonnegative_bound(
        &mut builder,
        v_max_name(),
        &velocity_bound_value(),
        "v_max_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        gamma_bound_name(),
        &gamma_bound_default(),
        "gamma_bound_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        gravity_name(),
        &gravity_bound_value(),
        "gravity_bound",
    )?;
    append_nonnegative_bound(&mut builder, k_sg_name(), &k_sg_bound(), "k_sg_bound")?;

    // Non-zero constraints on public parameters
    append_nonzero_constraint(&mut builder, q_max_name(), "q_max_nonzero")?;
    append_nonzero_constraint(&mut builder, q_dot_max_name(), "q_dot_max_nonzero")?;
    append_nonzero_constraint(&mut builder, v_max_name(), "v_max_nonzero")?;
    append_nonzero_constraint(&mut builder, gamma_bound_name(), "gamma_bound_nonzero")?;
    append_nonzero_constraint(&mut builder, gravity_name(), "gravity_nonzero")?;
    append_nonzero_constraint(&mut builder, k_sg_name(), "k_sg_nonzero")?;

    // -----------------------------------------------------------------------
    // Scalar private inputs
    // -----------------------------------------------------------------------
    builder.private_input(altitude_name())?;
    builder.private_input(velocity_name())?;
    builder.private_input(gamma_name())?;
    builder.private_input(mass_input_name())?;
    builder.private_input(sref_name())?;
    builder.private_input(cd_name())?;
    builder.private_input(cl_name())?;
    builder.private_input(rn_name())?;
    expected_inputs.push(altitude_name().to_string());
    expected_inputs.push(velocity_name().to_string());
    expected_inputs.push(gamma_name().to_string());
    expected_inputs.push(mass_input_name().to_string());
    expected_inputs.push(sref_name().to_string());
    expected_inputs.push(cd_name().to_string());
    expected_inputs.push(cl_name().to_string());
    expected_inputs.push(rn_name().to_string());

    // Bound-check scalar private inputs
    append_nonnegative_bound(
        &mut builder,
        altitude_name(),
        &altitude_bound(),
        "initial_altitude_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        velocity_name(),
        &velocity_bound_value(),
        "initial_velocity_bound",
    )?;
    append_signed_bound(
        &mut builder,
        gamma_name(),
        &gamma_bound_default(),
        "initial_gamma_bound",
    )?;
    append_nonnegative_bound(
        &mut builder,
        mass_input_name(),
        &mass_bound_value(),
        "mass_bound",
    )?;
    append_nonzero_constraint(&mut builder, mass_input_name(), "mass_nonzero")?;
    append_nonnegative_bound(&mut builder, sref_name(), &area_bound(), "sref_bound")?;
    append_nonzero_constraint(&mut builder, sref_name(), "sref_nonzero")?;
    append_nonnegative_bound(&mut builder, cd_name(), &coeff_bound(), "cd_bound")?;
    append_nonnegative_bound(&mut builder, cl_name(), &coeff_bound(), "cl_bound")?;
    append_nonnegative_bound(&mut builder, rn_name(), &nose_radius_bound(), "rn_bound")?;
    append_nonzero_constraint(&mut builder, rn_name(), "rn_nonzero")?;
    append_nonzero_constraint(&mut builder, velocity_name(), "initial_velocity_nonzero")?;

    // -----------------------------------------------------------------------
    // Per-step private inputs
    // -----------------------------------------------------------------------
    for step in 0..steps {
        let bc = bank_cos_name(step);
        let sg = sin_gamma_input_name(step);
        let cg = cos_gamma_input_name(step);
        let rho = rho_name(step);
        builder.private_input(&bc)?;
        builder.private_input(&sg)?;
        builder.private_input(&cg)?;
        builder.private_input(&rho)?;
        expected_inputs.push(bc.clone());
        expected_inputs.push(sg.clone());
        expected_inputs.push(cg.clone());
        expected_inputs.push(rho.clone());

        // Bound checks
        append_signed_bound(
            &mut builder,
            &bc,
            &bank_cos_bound(),
            &format!("step_{step}_bank_cos_bound"),
        )?;
        append_signed_bound(
            &mut builder,
            &sg,
            &trig_bound(),
            &format!("step_{step}_sin_gamma_bound"),
        )?;
        append_signed_bound(
            &mut builder,
            &cg,
            &trig_bound(),
            &format!("step_{step}_cos_gamma_bound"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &rho,
            &density_bound(),
            &format!("step_{step}_rho_bound"),
        )?;
    }

    // -----------------------------------------------------------------------
    // Per-step dynamics constraints
    // -----------------------------------------------------------------------
    for step in 0..steps {
        let h_name = h_state_name(step);
        let v_name_s = v_state_name(step);
        let gamma_name_s = gamma_state_name(step);
        let sg = sin_gamma_input_name(step);
        let cg = cos_gamma_input_name(step);
        let rho_s = rho_name(step);
        let bc = bank_cos_name(step);

        // (a) Trig identity: sin^2 + cos^2 + residual = SCALE^2
        let trig_res = trig_residual_name(step);
        builder.private_signal(&trig_res)?;
        builder.constrain_equal(
            add_expr(vec![
                mul_expr(signal_expr(&sg), signal_expr(&sg)),
                mul_expr(signal_expr(&cg), signal_expr(&cg)),
                signal_expr(&trig_res),
            ]),
            const_expr(&fixed_scale_squared()),
        )?;
        // Range-bound the residual (generous: up to 2*SCALE)
        let trig_residual_max = &fixed_scale() * two();
        builder.constrain_range(&trig_res, bits_for_bound(&trig_residual_max))?;

        // (b) V^2 signal
        let v_sq = v_sq_signal_name(step);
        builder.private_signal(&v_sq)?;
        builder.constrain_equal(
            signal_expr(&v_sq),
            mul_expr(signal_expr(&v_name_s), signal_expr(&v_name_s)),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &v_sq,
            &v_sq_bound(),
            &format!("step_{step}_v_sq_bound"),
        )?;

        // (c) rho * V^2 / SCALE  (intermediate for dynamic pressure)
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&rho_s), signal_expr(&v_sq)),
            const_expr(&fixed_scale()),
            &rho_v_sq_signal_name(step),
            &rho_v_sq_remainder_name(step),
            &rho_v_sq_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_rho_v_sq"),
        )?;

        // (d) Dynamic pressure: q = rho_v_sq / (2 * SCALE)
        append_exact_division_constraints(
            &mut builder,
            signal_expr(&rho_v_sq_signal_name(step)),
            const_expr(&(two() * fixed_scale())),
            &q_signal_name(step),
            &q_remainder_name(step),
            &q_slack_signal_name(step),
            &(two() * fixed_scale()),
            &format!("step_{step}_q"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &q_signal_name(step),
            &dynamic_pressure_bound(),
            &format!("step_{step}_q_bound"),
        )?;

        // (e) Drag force: D = q * S_ref * C_D / SCALE^2
        // Three scaled factors multiply to SCALE^3; divide by SCALE^2 leaves SCALE^1
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&q_signal_name(step)),
                mul_expr(signal_expr(sref_name()), signal_expr(cd_name())),
            ),
            const_expr(&fixed_scale_squared()),
            &drag_signal_name(step),
            &drag_remainder_signal_name(step),
            &drag_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_drag"),
        )?;

        // (f) Lift coefficient product: lift_cos = C_L * cos(sigma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(cl_name()), signal_expr(&bc)),
            const_expr(&fixed_scale()),
            &lift_cos_signal_name(step),
            &lift_cos_remainder_signal_name(step),
            &lift_cos_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_lift_cos"),
        )?;

        // (g) Lift force: L = q * S_ref * lift_cos / SCALE^2
        // Three scaled factors multiply to SCALE^3; divide by SCALE^2 leaves SCALE^1
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&q_signal_name(step)),
                mul_expr(
                    signal_expr(sref_name()),
                    signal_expr(&lift_cos_signal_name(step)),
                ),
            ),
            const_expr(&fixed_scale_squared()),
            &lift_signal_name(step),
            &lift_remainder_signal_name(step),
            &lift_slack_signal_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_lift"),
        )?;

        // (h) Drag acceleration: drag_accel = D * SCALE / m
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&drag_signal_name(step)),
                const_expr(&fixed_scale()),
            ),
            signal_expr(mass_input_name()),
            &drag_accel_signal_name(step),
            &drag_accel_remainder_name(step),
            &drag_accel_slack_name(step),
            &mass_bound_value(),
            &format!("step_{step}_drag_accel"),
        )?;
        append_signed_bound(
            &mut builder,
            &drag_accel_signal_name(step),
            &acceleration_bound(),
            &format!("step_{step}_drag_accel_bound"),
        )?;

        // (i) Lift acceleration: lift_accel = L * SCALE / m
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&lift_signal_name(step)),
                const_expr(&fixed_scale()),
            ),
            signal_expr(mass_input_name()),
            &lift_accel_signal_name(step),
            &lift_accel_remainder_name(step),
            &lift_accel_slack_name(step),
            &mass_bound_value(),
            &format!("step_{step}_lift_accel"),
        )?;
        append_signed_bound(
            &mut builder,
            &lift_accel_signal_name(step),
            &acceleration_bound(),
            &format!("step_{step}_lift_accel_bound"),
        )?;

        // (j) g * sin(gamma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(gravity_name()), signal_expr(&sg)),
            const_expr(&fixed_scale()),
            &g_sin_gamma_signal_name(step),
            &g_sin_gamma_remainder_name(step),
            &g_sin_gamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_g_sin_gamma"),
        )?;

        // (k) dv_accel = -drag_accel - g_sin_gamma
        let dv_accel_name = dv_accel_signal_name(step);
        builder.private_signal(&dv_accel_name)?;
        builder.constrain_equal(
            add_expr(vec![
                signal_expr(&dv_accel_name),
                signal_expr(&drag_accel_signal_name(step)),
                signal_expr(&g_sin_gamma_signal_name(step)),
            ]),
            const_expr(&zero()),
        )?;
        append_signed_bound(
            &mut builder,
            &dv_accel_name,
            &acceleration_bound(),
            &format!("step_{step}_dv_accel_bound"),
        )?;

        // (l) dV = dv_accel * dt / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&dv_accel_name), const_expr(&dt_scaled())),
            const_expr(&fixed_scale()),
            &dv_signal_name(step),
            &dv_remainder_name(step),
            &dv_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_dv"),
        )?;
        append_signed_bound(
            &mut builder,
            &dv_signal_name(step),
            &velocity_delta_bound(),
            &format!("step_{step}_dv_bound"),
        )?;

        // (m) V * sin(gamma) intermediate
        let v_sin = v_sin_signal_name(step);
        builder.private_signal(&v_sin)?;
        builder.constrain_equal(
            signal_expr(&v_sin),
            mul_expr(signal_expr(&v_name_s), signal_expr(&sg)),
        )?;

        // (n) dh = V * sin(gamma) * dt / SCALE^2
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&v_sin), const_expr(&dt_scaled())),
            const_expr(&fixed_scale_squared()),
            &dh_signal_name(step),
            &dh_remainder_name(step),
            &dh_slack_name(step),
            &exact_division_remainder_bound_for_scale_squared(),
            &format!("step_{step}_dh"),
        )?;
        append_signed_bound(
            &mut builder,
            &dh_signal_name(step),
            &altitude_delta_bound(),
            &format!("step_{step}_dh_bound"),
        )?;

        // (o) lift_over_v = lift_accel * SCALE / V
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&lift_accel_signal_name(step)),
                const_expr(&fixed_scale()),
            ),
            signal_expr(&v_name_s),
            &lift_over_v_signal_name(step),
            &lift_over_v_remainder_name(step),
            &lift_over_v_slack_name(step),
            &velocity_bound_value(),
            &format!("step_{step}_lift_over_v"),
        )?;

        // (p) g * cos(gamma) / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(gravity_name()), signal_expr(&cg)),
            const_expr(&fixed_scale()),
            &g_cos_gamma_signal_name(step),
            &g_cos_gamma_remainder_name(step),
            &g_cos_gamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_g_cos_gamma"),
        )?;

        // (q) gcos_over_v = g_cos_gamma * SCALE / V
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&g_cos_gamma_signal_name(step)),
                const_expr(&fixed_scale()),
            ),
            signal_expr(&v_name_s),
            &gcos_over_v_signal_name(step),
            &gcos_over_v_remainder_name(step),
            &gcos_over_v_slack_name(step),
            &velocity_bound_value(),
            &format!("step_{step}_gcos_over_v"),
        )?;

        // (r) dgamma_accel = lift_over_v - gcos_over_v
        let dgamma_accel = dgamma_accel_signal_name(step);
        builder.private_signal(&dgamma_accel)?;
        builder.constrain_equal(
            signal_expr(&dgamma_accel),
            sub_expr(
                signal_expr(&lift_over_v_signal_name(step)),
                signal_expr(&gcos_over_v_signal_name(step)),
            ),
        )?;

        // (s) dgamma = dgamma_accel * dt / SCALE
        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&dgamma_accel), const_expr(&dt_scaled())),
            const_expr(&fixed_scale()),
            &dgamma_signal_name(step),
            &dgamma_remainder_name(step),
            &dgamma_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_dgamma"),
        )?;
        append_signed_bound(
            &mut builder,
            &dgamma_signal_name(step),
            &gamma_delta_bound(),
            &format!("step_{step}_dgamma_bound"),
        )?;

        // (t) Next state signals
        let next_h = h_state_name(step + 1);
        let next_v = v_state_name(step + 1);
        let next_gamma = gamma_state_name(step + 1);
        builder.private_signal(&next_h)?;
        builder.private_signal(&next_v)?;
        builder.private_signal(&next_gamma)?;

        builder.constrain_equal(
            signal_expr(&next_h),
            add_expr(vec![
                signal_expr(&h_name),
                signal_expr(&dh_signal_name(step)),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_v),
            add_expr(vec![
                signal_expr(&v_name_s),
                signal_expr(&dv_signal_name(step)),
            ]),
        )?;
        builder.constrain_equal(
            signal_expr(&next_gamma),
            add_expr(vec![
                signal_expr(&gamma_name_s),
                signal_expr(&dgamma_signal_name(step)),
            ]),
        )?;

        // Bound next state
        append_nonnegative_bound(
            &mut builder,
            &next_h,
            &altitude_bound(),
            &format!("state_{}_altitude_bound", step + 1),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &next_v,
            &velocity_bound_value(),
            &format!("state_{}_velocity_bound", step + 1),
        )?;
        append_nonzero_constraint(
            &mut builder,
            &next_v,
            &format!("state_{}_velocity_nonzero", step + 1),
        )?;
        append_signed_bound(
            &mut builder,
            &next_gamma,
            &gamma_bound_default(),
            &format!("state_{}_gamma_bound", step + 1),
        )?;

        // (u) Heating-rate support: q_dot = (k_sg * sqrt(rho / r_n) * V^3)
        append_exact_division_constraints(
            &mut builder,
            signal_expr(&v_sq),
            const_expr(&fixed_scale()),
            &v_sq_fp_signal_name(step),
            &v_sq_fp_remainder_name(step),
            &v_sq_fp_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_v_sq_fp"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &v_sq_fp_signal_name(step),
            &v_sq_fp_bound(),
            &format!("step_{step}_v_sq_fp_bound"),
        )?;

        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&v_sq_fp_signal_name(step)),
                signal_expr(&v_name_s),
            ),
            const_expr(&fixed_scale()),
            &v_cubed_fp_signal_name(step),
            &v_cubed_remainder_name(step),
            &v_cubed_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_v_cubed_fp"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &v_cubed_fp_signal_name(step),
            &v_cubed_fp_bound(),
            &format!("step_{step}_v_cubed_fp_bound"),
        )?;

        append_exact_division_constraints(
            &mut builder,
            mul_expr(signal_expr(&rho_s), const_expr(&fixed_scale())),
            signal_expr(rn_name()),
            &rho_over_rn_signal_name(step),
            &rho_over_rn_remainder_name(step),
            &rho_over_rn_slack_name(step),
            &nose_radius_bound(),
            &format!("step_{step}_rho_over_rn"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &rho_over_rn_signal_name(step),
            &rho_over_rn_bound(),
            &format!("step_{step}_rho_over_rn_bound"),
        )?;

        append_floor_sqrt_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&rho_over_rn_signal_name(step)),
                const_expr(&fixed_scale()),
            ),
            &sqrt_rho_over_rn_signal_name(step),
            &sqrt_rho_over_rn_remainder_name(step),
            &sqrt_rho_over_rn_upper_slack_name(step),
            &sqrt_rho_over_rn_bound(),
            &sqrt_support_bound(&sqrt_rho_over_rn_bound()),
            &format!("step_{step}_sqrt_rho_over_rn"),
        )?;

        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(k_sg_name()),
                signal_expr(&sqrt_rho_over_rn_signal_name(step)),
            ),
            const_expr(&fixed_scale()),
            &heating_factor_signal_name(step),
            &heating_factor_remainder_name(step),
            &heating_factor_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_heating_factor"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &heating_factor_signal_name(step),
            &heating_factor_bound(),
            &format!("step_{step}_heating_factor_bound"),
        )?;

        let q_dot = q_dot_signal_name(step);
        append_exact_division_constraints(
            &mut builder,
            mul_expr(
                signal_expr(&heating_factor_signal_name(step)),
                signal_expr(&v_cubed_fp_signal_name(step)),
            ),
            const_expr(&fixed_scale()),
            &q_dot,
            &q_dot_remainder_name(step),
            &q_dot_slack_name(step),
            &exact_division_remainder_bound_for_scale(),
            &format!("step_{step}_q_dot"),
        )?;
        append_nonnegative_bound(
            &mut builder,
            &q_dot,
            &q_dot_max_bound(),
            &format!("step_{step}_q_dot_bound"),
        )?;

        // (v) Safety envelope checks
        // q_i <= q_max:  q_max = q_i + q_safety_slack, slack >= 0
        let q_slack = q_safety_slack_name(step);
        builder.private_signal(&q_slack)?;
        let q_slack_anchor = nonlinear_anchor_name(&q_slack);
        builder.private_signal(&q_slack_anchor)?;
        builder.constrain_equal(
            signal_expr(q_max_name()),
            add_expr(vec![
                signal_expr(&q_signal_name(step)),
                signal_expr(&q_slack),
            ]),
        )?;
        builder.constrain_range(&q_slack, bits_for_bound(&q_max_bound()))?;
        builder.constrain_equal(
            signal_expr(&q_slack_anchor),
            mul_expr(signal_expr(&q_slack), signal_expr(&q_slack)),
        )?;

        // q_dot_i <= q_dot_max
        let qd_slack = q_dot_safety_slack_name(step);
        builder.private_signal(&qd_slack)?;
        let qd_slack_anchor = nonlinear_anchor_name(&qd_slack);
        builder.private_signal(&qd_slack_anchor)?;
        builder.constrain_equal(
            signal_expr(q_dot_max_name()),
            add_expr(vec![signal_expr(&q_dot), signal_expr(&qd_slack)]),
        )?;
        builder.constrain_range(&qd_slack, bits_for_bound(&q_dot_max_bound()))?;
        builder.constrain_equal(
            signal_expr(&qd_slack_anchor),
            mul_expr(signal_expr(&qd_slack), signal_expr(&qd_slack)),
        )?;

        // h_i >= h_min: h_i = h_min + h_safety_slack, slack >= 0
        let h_slack = h_safety_slack_signal_name(step);
        builder.private_signal(&h_slack)?;
        let h_slack_anchor = nonlinear_anchor_name(&h_slack);
        builder.private_signal(&h_slack_anchor)?;
        builder.constrain_equal(
            signal_expr(&h_name),
            add_expr(vec![signal_expr(h_min_name()), signal_expr(&h_slack)]),
        )?;
        builder.constrain_range(&h_slack, bits_for_bound(&altitude_bound()))?;
        builder.constrain_equal(
            signal_expr(&h_slack_anchor),
            mul_expr(signal_expr(&h_slack), signal_expr(&h_slack)),
        )?;

        // V_i <= v_max: v_max = V_i + v_safety_slack, slack >= 0
        let v_slack = v_safety_slack_signal_name(step);
        builder.private_signal(&v_slack)?;
        let v_slack_anchor = nonlinear_anchor_name(&v_slack);
        builder.private_signal(&v_slack_anchor)?;
        builder.constrain_equal(
            signal_expr(v_max_name()),
            add_expr(vec![signal_expr(&v_name_s), signal_expr(&v_slack)]),
        )?;
        builder.constrain_range(&v_slack, bits_for_bound(&velocity_bound_value()))?;
        builder.constrain_equal(
            signal_expr(&v_slack_anchor),
            mul_expr(signal_expr(&v_slack), signal_expr(&v_slack)),
        )?;

        // gamma within bounds (already constrained via signed_bound on next_gamma)
    }

    // -----------------------------------------------------------------------
    // Running max for peak dynamic pressure
    // -----------------------------------------------------------------------
    let run_max_q_0 = running_max_q_name(0);
    builder.private_signal(&run_max_q_0)?;
    builder.constrain_equal(signal_expr(&run_max_q_0), signal_expr(&q_signal_name(0)))?;
    append_nonnegative_bound(
        &mut builder,
        &run_max_q_0,
        &dynamic_pressure_bound(),
        "state_0_running_max_q_bound",
    )?;

    for step in 1..steps {
        let current = running_max_q_name(step);
        let previous = running_max_q_name(step - 1);
        let prev_slack = running_max_q_prev_slack_name(step);
        let curr_slack = running_max_q_curr_slack_name(step);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_bound(
            &mut builder,
            &current,
            &dynamic_pressure_bound(),
            &format!("state_{step}_running_max_q_bound"),
        )?;
        // current = previous + prev_slack  (current >= previous)
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&previous), signal_expr(&prev_slack)]),
        )?;
        // current = q_i + curr_slack  (current >= q_i)
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![
                signal_expr(&q_signal_name(step)),
                signal_expr(&curr_slack),
            ]),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&dynamic_pressure_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&dynamic_pressure_bound()))?;
        // Exactly one of prev_slack or curr_slack is zero (either we kept previous or took new)
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(peak_q_output_name())?;
    let last_max_q = running_max_q_name(if steps > 0 { steps - 1 } else { 0 });
    builder.constrain_equal(signal_expr(peak_q_output_name()), signal_expr(&last_max_q))?;
    append_nonnegative_bound(
        &mut builder,
        peak_q_output_name(),
        &dynamic_pressure_bound(),
        "peak_q_public_bound",
    )?;

    // -----------------------------------------------------------------------
    // Running max for peak heating rate
    // -----------------------------------------------------------------------
    let run_max_qd_0 = running_max_q_dot_name(0);
    builder.private_signal(&run_max_qd_0)?;
    builder.constrain_equal(
        signal_expr(&run_max_qd_0),
        signal_expr(&q_dot_signal_name(0)),
    )?;
    append_nonnegative_bound(
        &mut builder,
        &run_max_qd_0,
        &q_dot_max_bound(),
        "state_0_running_max_q_dot_bound",
    )?;

    for step in 1..steps {
        let current = running_max_q_dot_name(step);
        let previous = running_max_q_dot_name(step - 1);
        let prev_slack = running_max_q_dot_prev_slack_name(step);
        let curr_slack = running_max_q_dot_curr_slack_name(step);
        builder.private_signal(&current)?;
        builder.private_signal(&prev_slack)?;
        builder.private_signal(&curr_slack)?;
        append_nonnegative_bound(
            &mut builder,
            &current,
            &q_dot_max_bound(),
            &format!("state_{step}_running_max_q_dot_bound"),
        )?;
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![signal_expr(&previous), signal_expr(&prev_slack)]),
        )?;
        builder.constrain_equal(
            signal_expr(&current),
            add_expr(vec![
                signal_expr(&q_dot_signal_name(step)),
                signal_expr(&curr_slack),
            ]),
        )?;
        builder.constrain_range(&prev_slack, bits_for_bound(&q_dot_max_bound()))?;
        builder.constrain_range(&curr_slack, bits_for_bound(&q_dot_max_bound()))?;
        builder.constrain_equal(
            mul_expr(signal_expr(&prev_slack), signal_expr(&curr_slack)),
            const_expr(&zero()),
        )?;
    }

    builder.public_output(peak_q_dot_output_name())?;
    let last_max_qd = running_max_q_dot_name(if steps > 0 { steps - 1 } else { 0 });
    builder.constrain_equal(
        signal_expr(peak_q_dot_output_name()),
        signal_expr(&last_max_qd),
    )?;
    append_nonnegative_bound(
        &mut builder,
        peak_q_dot_output_name(),
        &q_dot_max_bound(),
        "peak_q_dot_public_bound",
    )?;

    // -----------------------------------------------------------------------
    // Trajectory Poseidon commitment
    // -----------------------------------------------------------------------
    builder.public_output(trajectory_commitment_output_name())?;
    let mut previous_digest = const_expr(&trajectory_seed_tag());
    for step in 0..=steps {
        let state_digest = append_poseidon_hash(
            &mut builder,
            &format!("trajectory_step_{step}_state"),
            [
                signal_expr(&h_state_name(step)),
                signal_expr(&v_state_name(step)),
                signal_expr(&gamma_state_name(step)),
                const_expr(&BigInt::from(step as u64)),
            ],
        )?;
        previous_digest = {
            let chain_digest = append_poseidon_hash(
                &mut builder,
                &format!("trajectory_step_{step}_chain"),
                [
                    signal_expr(&state_digest),
                    previous_digest,
                    const_expr(&trajectory_step_tag(step)),
                    const_expr(&zero()),
                ],
            )?;
            signal_expr(&chain_digest)
        };
    }
    builder.constrain_equal(
        signal_expr(trajectory_commitment_output_name()),
        previous_digest,
    )?;

    // -----------------------------------------------------------------------
    // Terminal state commitment
    // -----------------------------------------------------------------------
    builder.public_output(terminal_state_commitment_output_name())?;
    let terminal_digest = append_poseidon_hash(
        &mut builder,
        "terminal_state_commitment",
        [
            signal_expr(&h_state_name(steps)),
            signal_expr(&v_state_name(steps)),
            signal_expr(&gamma_state_name(steps)),
            const_expr(&terminal_state_tag()),
        ],
    )?;
    builder.constrain_equal(
        signal_expr(terminal_state_commitment_output_name()),
        signal_expr(&terminal_digest),
    )?;

    // -----------------------------------------------------------------------
    // Constraint satisfaction (fail-closed certificate)
    // -----------------------------------------------------------------------
    builder.public_output(constraint_satisfaction_output_name())?;
    builder.constrain_boolean(constraint_satisfaction_output_name())?;
    builder.constrain_equal(
        signal_expr(constraint_satisfaction_output_name()),
        const_expr(&one()),
    )?;

    // -----------------------------------------------------------------------
    // Build
    // -----------------------------------------------------------------------
    let sample_inputs = reentry_sample_inputs_for_steps(steps);
    let mut violation_inputs = sample_inputs.clone();
    violation_inputs.insert(mass_input_name().to_string(), FieldElement::ZERO);

    Ok(TemplateProgram {
        program: builder.build()?,
        expected_inputs,
        public_outputs,
        sample_inputs,
        violation_inputs,
        description: if steps == PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS {
            PRIVATE_REENTRY_THERMAL_DESCRIPTION
        } else {
            PRIVATE_REENTRY_THERMAL_TEST_HELPER_DESCRIPTION
        },
    })
}

// ---------------------------------------------------------------------------
// Public showcase entry points (with stacker)
// ---------------------------------------------------------------------------

pub fn build_private_reentry_thermal_program(steps: usize) -> ZkfResult<zkf_core::Program> {
    private_reentry_thermal_showcase_with_steps(steps).map(|template| template.program)
}

pub fn private_reentry_thermal_showcase() -> ZkfResult<TemplateProgram> {
    private_reentry_thermal_showcase_with_steps(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_reentry_thermal_showcase_with_steps(steps: usize) -> ZkfResult<TemplateProgram> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_reentry_thermal_showcase_inner(steps)
    })
}

pub fn private_reentry_thermal_sample_inputs() -> WitnessInputs {
    reentry_sample_inputs_for_steps(PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

// ---------------------------------------------------------------------------
// Witness generation
// ---------------------------------------------------------------------------

fn private_reentry_thermal_witness_inner(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    if steps == 0 {
        return Err(ZkfError::InvalidArtifact(
            "private reentry thermal witness generation requires at least one integration step"
                .to_string(),
        ));
    }

    let parameters = load_public_parameters(inputs)?;
    let mut values = BTreeMap::<String, FieldElement>::new();
    write_public_parameter_support(&mut values, &parameters)?;

    // Read scalar private inputs
    let h0 = read_input(inputs, altitude_name())?;
    let v0 = read_input(inputs, velocity_name())?;
    let gamma0 = read_input(inputs, gamma_name())?;
    let mass = read_input(inputs, mass_input_name())?;
    let s_ref = read_input(inputs, sref_name())?;
    let c_d = read_input(inputs, cd_name())?;
    let c_l = read_input(inputs, cl_name())?;
    let r_n = read_input(inputs, rn_name())?;

    // Validate scalar private inputs
    ensure_nonnegative_le(altitude_name(), &h0, &altitude_bound())?;
    ensure_nonnegative_le(velocity_name(), &v0, &velocity_bound_value())?;
    ensure_positive_le(velocity_name(), &v0, &velocity_bound_value())?;
    ensure_abs_le(gamma_name(), &gamma0, &gamma_bound_default())?;
    ensure_positive_le(mass_input_name(), &mass, &mass_bound_value())?;
    ensure_positive_le(sref_name(), &s_ref, &area_bound())?;
    ensure_nonnegative_le(cd_name(), &c_d, &coeff_bound())?;
    ensure_nonnegative_le(cl_name(), &c_l, &coeff_bound())?;
    ensure_positive_le(rn_name(), &r_n, &nose_radius_bound())?;

    // Write scalar private input support
    write_nonnegative_bound_support(
        &mut values,
        altitude_name(),
        &h0,
        &altitude_bound(),
        "initial_altitude_bound",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        velocity_name(),
        &v0,
        &velocity_bound_value(),
        "initial_velocity_bound",
    )?;
    write_signed_bound_support(
        &mut values,
        &gamma0,
        &gamma_bound_default(),
        "initial_gamma_bound",
    )?;
    write_value(&mut values, gamma_name(), gamma0.clone());
    write_nonnegative_bound_support(
        &mut values,
        mass_input_name(),
        &mass,
        &mass_bound_value(),
        "mass_bound",
    )?;
    write_nonzero_inverse_support(&mut values, &mass, "mass_nonzero")?;
    write_nonnegative_bound_support(
        &mut values,
        sref_name(),
        &s_ref,
        &area_bound(),
        "sref_bound",
    )?;
    write_nonzero_inverse_support(&mut values, &s_ref, "sref_nonzero")?;
    write_nonnegative_bound_support(&mut values, cd_name(), &c_d, &coeff_bound(), "cd_bound")?;
    write_nonnegative_bound_support(&mut values, cl_name(), &c_l, &coeff_bound(), "cl_bound")?;
    write_nonnegative_bound_support(
        &mut values,
        rn_name(),
        &r_n,
        &nose_radius_bound(),
        "rn_bound",
    )?;
    write_nonzero_inverse_support(&mut values, &r_n, "rn_nonzero")?;
    write_nonzero_inverse_support(&mut values, &v0, "initial_velocity_nonzero")?;

    // Read per-step inputs and validate
    let mut bank_cosines = Vec::with_capacity(steps);
    let mut sin_gammas = Vec::with_capacity(steps);
    let mut cos_gammas = Vec::with_capacity(steps);
    let mut densities = Vec::with_capacity(steps);

    for step in 0..steps {
        let bc = read_input(inputs, &bank_cos_name(step))?;
        let sg = read_input(inputs, &sin_gamma_input_name(step))?;
        let cg = read_input(inputs, &cos_gamma_input_name(step))?;
        let rho = read_input(inputs, &rho_name(step))?;

        ensure_abs_le(&bank_cos_name(step), &bc, &bank_cos_bound())?;
        ensure_abs_le(&sin_gamma_input_name(step), &sg, &trig_bound())?;
        ensure_abs_le(&cos_gamma_input_name(step), &cg, &trig_bound())?;
        ensure_nonnegative_le(&rho_name(step), &rho, &density_bound())?;

        write_value(&mut values, bank_cos_name(step), bc.clone());
        write_signed_bound_support(
            &mut values,
            &bc,
            &bank_cos_bound(),
            &format!("step_{step}_bank_cos_bound"),
        )?;
        write_value(&mut values, sin_gamma_input_name(step), sg.clone());
        write_signed_bound_support(
            &mut values,
            &sg,
            &trig_bound(),
            &format!("step_{step}_sin_gamma_bound"),
        )?;
        write_value(&mut values, cos_gamma_input_name(step), cg.clone());
        write_signed_bound_support(
            &mut values,
            &cg,
            &trig_bound(),
            &format!("step_{step}_cos_gamma_bound"),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            rho_name(step),
            &rho,
            &density_bound(),
            &format!("step_{step}_rho_bound"),
        )?;

        bank_cosines.push(bc);
        sin_gammas.push(sg);
        cos_gammas.push(cg);
        densities.push(rho);
    }

    // Forward-propagate state and write witness values
    let mut altitudes = Vec::with_capacity(steps + 1);
    let mut velocities = Vec::with_capacity(steps + 1);
    let mut gammas = Vec::with_capacity(steps + 1);
    let mut q_values = Vec::with_capacity(steps);
    let mut q_dot_values = Vec::with_capacity(steps);

    let mut current_h = h0.clone();
    let mut current_v = v0.clone();
    let mut current_gamma = gamma0.clone();

    altitudes.push(current_h.clone());
    velocities.push(current_v.clone());
    gammas.push(current_gamma.clone());

    for step in 0..steps {
        let step_result = compute_step_dynamics(
            &current_h,
            &current_v,
            &current_gamma,
            &sin_gammas[step],
            &cos_gammas[step],
            &densities[step],
            &bank_cosines[step],
            &mass,
            &s_ref,
            &c_d,
            &c_l,
            &r_n,
            &parameters.k_sg,
            &parameters,
        )?;

        // Write trig identity support
        write_value(
            &mut values,
            trig_residual_name(step),
            step_result.trig_identity_residual.clone(),
        );

        // Write V^2
        write_nonnegative_bound_support(
            &mut values,
            v_sq_signal_name(step),
            &step_result.v_sq,
            &v_sq_bound(),
            &format!("step_{step}_v_sq_bound"),
        )?;

        // Write V^2 / SCALE support for the heating lane.
        write_value(
            &mut values,
            v_sq_fp_signal_name(step),
            step_result.v_sq_fp.clone(),
        );
        write_value(
            &mut values,
            v_sq_fp_remainder_name(step),
            step_result.v_sq_fp_remainder.clone(),
        );
        write_value(
            &mut values,
            v_sq_fp_slack_name(step),
            step_result.v_sq_fp_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_v_sq_fp"),
            &step_result.v_sq_fp_slack,
        );
        write_nonnegative_bound_support(
            &mut values,
            v_sq_fp_signal_name(step),
            &step_result.v_sq_fp,
            &v_sq_fp_bound(),
            &format!("step_{step}_v_sq_fp_bound"),
        )?;

        // Write V^3 fixed-point support for the heating lane.
        write_value(
            &mut values,
            v_cubed_fp_signal_name(step),
            step_result.v_cubed_fp.clone(),
        );
        write_value(
            &mut values,
            v_cubed_remainder_name(step),
            step_result.v_cubed_remainder.clone(),
        );
        write_value(
            &mut values,
            v_cubed_slack_name(step),
            step_result.v_cubed_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_v_cubed_fp"),
            &step_result.v_cubed_slack,
        );
        write_nonnegative_bound_support(
            &mut values,
            v_cubed_fp_signal_name(step),
            &step_result.v_cubed_fp,
            &v_cubed_fp_bound(),
            &format!("step_{step}_v_cubed_fp_bound"),
        )?;

        // Write rho*V^2/SCALE division support
        write_value(
            &mut values,
            rho_v_sq_signal_name(step),
            step_result.rho_v_sq.clone(),
        );
        write_value(
            &mut values,
            rho_v_sq_remainder_name(step),
            step_result.rho_v_sq_remainder.clone(),
        );
        write_value(
            &mut values,
            rho_v_sq_slack_name(step),
            step_result.rho_v_sq_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_rho_v_sq"),
            &step_result.rho_v_sq_slack,
        );

        // Write dynamic pressure division support
        write_value(&mut values, q_signal_name(step), step_result.q_i.clone());
        write_value(
            &mut values,
            q_remainder_name(step),
            step_result.q_i_remainder.clone(),
        );
        write_value(
            &mut values,
            q_slack_signal_name(step),
            step_result.q_i_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_q"),
            &step_result.q_i_slack,
        );
        write_nonnegative_bound_support(
            &mut values,
            q_signal_name(step),
            &step_result.q_i,
            &dynamic_pressure_bound(),
            &format!("step_{step}_q_bound"),
        )?;

        // Write drag force division support
        write_value(
            &mut values,
            drag_signal_name(step),
            step_result.drag_force.clone(),
        );
        write_value(
            &mut values,
            drag_remainder_signal_name(step),
            step_result.drag_remainder.clone(),
        );
        write_value(
            &mut values,
            drag_slack_signal_name(step),
            step_result.drag_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_drag"),
            &step_result.drag_slack,
        );

        // Write lift_cos division support
        write_value(
            &mut values,
            lift_cos_signal_name(step),
            step_result.lift_cos.clone(),
        );
        write_value(
            &mut values,
            lift_cos_remainder_signal_name(step),
            step_result.lift_cos_remainder.clone(),
        );
        write_value(
            &mut values,
            lift_cos_slack_signal_name(step),
            step_result.lift_cos_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_lift_cos"),
            &step_result.lift_cos_slack,
        );

        // Write lift force division support
        write_value(
            &mut values,
            lift_signal_name(step),
            step_result.lift_force.clone(),
        );
        write_value(
            &mut values,
            lift_remainder_signal_name(step),
            step_result.lift_remainder.clone(),
        );
        write_value(
            &mut values,
            lift_slack_signal_name(step),
            step_result.lift_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_lift"),
            &step_result.lift_slack,
        );

        // Write drag accel division support
        write_value(
            &mut values,
            drag_accel_signal_name(step),
            step_result.drag_accel.clone(),
        );
        write_value(
            &mut values,
            drag_accel_remainder_name(step),
            step_result.drag_accel_remainder.clone(),
        );
        write_value(
            &mut values,
            drag_accel_slack_name(step),
            step_result.drag_accel_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_drag_accel"),
            &step_result.drag_accel_slack,
        );
        write_signed_bound_support(
            &mut values,
            &step_result.drag_accel,
            &acceleration_bound(),
            &format!("step_{step}_drag_accel_bound"),
        )?;

        // Write lift accel division support
        write_value(
            &mut values,
            lift_accel_signal_name(step),
            step_result.lift_accel.clone(),
        );
        write_value(
            &mut values,
            lift_accel_remainder_name(step),
            step_result.lift_accel_remainder.clone(),
        );
        write_value(
            &mut values,
            lift_accel_slack_name(step),
            step_result.lift_accel_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_lift_accel"),
            &step_result.lift_accel_slack,
        );
        write_signed_bound_support(
            &mut values,
            &step_result.lift_accel,
            &acceleration_bound(),
            &format!("step_{step}_lift_accel_bound"),
        )?;

        // Write g*sin(gamma)/SCALE division support
        write_value(
            &mut values,
            g_sin_gamma_signal_name(step),
            step_result.g_sin_gamma.clone(),
        );
        write_value(
            &mut values,
            g_sin_gamma_remainder_name(step),
            step_result.g_sin_gamma_remainder.clone(),
        );
        write_value(
            &mut values,
            g_sin_gamma_slack_name(step),
            step_result.g_sin_gamma_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_g_sin_gamma"),
            &step_result.g_sin_gamma_slack,
        );

        // Write dv_accel
        write_value(
            &mut values,
            dv_accel_signal_name(step),
            step_result.dv_accel.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &step_result.dv_accel,
            &acceleration_bound(),
            &format!("step_{step}_dv_accel_bound"),
        )?;

        // Write dv division support
        write_value(&mut values, dv_signal_name(step), step_result.dv.clone());
        write_value(
            &mut values,
            dv_remainder_name(step),
            step_result.dv_remainder.clone(),
        );
        write_value(
            &mut values,
            dv_slack_name(step),
            step_result.dv_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_dv"),
            &step_result.dv_slack,
        );
        write_signed_bound_support(
            &mut values,
            &step_result.dv,
            &velocity_delta_bound(),
            &format!("step_{step}_dv_bound"),
        )?;

        // Write v_sin intermediate
        write_value(
            &mut values,
            v_sin_signal_name(step),
            step_result.v_sin.clone(),
        );

        // Write dh division support
        write_value(&mut values, dh_signal_name(step), step_result.dh.clone());
        write_value(
            &mut values,
            dh_remainder_name(step),
            step_result.dh_remainder.clone(),
        );
        write_value(
            &mut values,
            dh_slack_name(step),
            step_result.dh_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_dh"),
            &step_result.dh_slack,
        );
        write_signed_bound_support(
            &mut values,
            &step_result.dh,
            &altitude_delta_bound(),
            &format!("step_{step}_dh_bound"),
        )?;

        // Write lift_over_v division support
        write_value(
            &mut values,
            lift_over_v_signal_name(step),
            step_result.lift_over_v.clone(),
        );
        write_value(
            &mut values,
            lift_over_v_remainder_name(step),
            step_result.lift_over_v_remainder.clone(),
        );
        write_value(
            &mut values,
            lift_over_v_slack_name(step),
            step_result.lift_over_v_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_lift_over_v"),
            &step_result.lift_over_v_slack,
        );

        // Write g*cos(gamma)/SCALE division support
        write_value(
            &mut values,
            g_cos_gamma_signal_name(step),
            step_result.g_cos_gamma.clone(),
        );
        write_value(
            &mut values,
            g_cos_gamma_remainder_name(step),
            step_result.g_cos_gamma_remainder.clone(),
        );
        write_value(
            &mut values,
            g_cos_gamma_slack_name(step),
            step_result.g_cos_gamma_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_g_cos_gamma"),
            &step_result.g_cos_gamma_slack,
        );

        // Write gcos_over_v division support
        write_value(
            &mut values,
            gcos_over_v_signal_name(step),
            step_result.gcos_over_v.clone(),
        );
        write_value(
            &mut values,
            gcos_over_v_remainder_name(step),
            step_result.gcos_over_v_remainder.clone(),
        );
        write_value(
            &mut values,
            gcos_over_v_slack_name(step),
            step_result.gcos_over_v_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_gcos_over_v"),
            &step_result.gcos_over_v_slack,
        );

        // Write dgamma_accel
        write_value(
            &mut values,
            dgamma_accel_signal_name(step),
            step_result.dgamma_accel.clone(),
        );

        // Write dgamma division support
        write_value(
            &mut values,
            dgamma_signal_name(step),
            step_result.dgamma.clone(),
        );
        write_value(
            &mut values,
            dgamma_remainder_name(step),
            step_result.dgamma_remainder.clone(),
        );
        write_value(
            &mut values,
            dgamma_slack_name(step),
            step_result.dgamma_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_dgamma"),
            &step_result.dgamma_slack,
        );
        write_signed_bound_support(
            &mut values,
            &step_result.dgamma,
            &gamma_delta_bound(),
            &format!("step_{step}_dgamma_bound"),
        )?;

        // Write next state
        write_nonnegative_bound_support(
            &mut values,
            h_state_name(step + 1),
            &step_result.next_altitude,
            &altitude_bound(),
            &format!("state_{}_altitude_bound", step + 1),
        )?;
        write_nonnegative_bound_support(
            &mut values,
            v_state_name(step + 1),
            &step_result.next_velocity,
            &velocity_bound_value(),
            &format!("state_{}_velocity_bound", step + 1),
        )?;
        write_nonzero_inverse_support(
            &mut values,
            &step_result.next_velocity,
            &format!("state_{}_velocity_nonzero", step + 1),
        )?;
        write_value(
            &mut values,
            gamma_state_name(step + 1),
            step_result.next_gamma.clone(),
        );
        write_signed_bound_support(
            &mut values,
            &step_result.next_gamma,
            &gamma_bound_default(),
            &format!("state_{}_gamma_bound", step + 1),
        )?;

        // Write heating-rate derivation support.
        write_value(
            &mut values,
            rho_over_rn_signal_name(step),
            step_result.rho_over_rn_fp.clone(),
        );
        write_value(
            &mut values,
            rho_over_rn_remainder_name(step),
            step_result.rho_over_rn_remainder.clone(),
        );
        write_value(
            &mut values,
            rho_over_rn_slack_name(step),
            step_result.rho_over_rn_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_rho_over_rn"),
            &step_result.rho_over_rn_slack,
        );
        write_nonnegative_bound_support(
            &mut values,
            rho_over_rn_signal_name(step),
            &step_result.rho_over_rn_fp,
            &rho_over_rn_bound(),
            &format!("step_{step}_rho_over_rn_bound"),
        )?;

        write_value(
            &mut values,
            sqrt_rho_over_rn_signal_name(step),
            step_result.sqrt_rho_over_rn_fp.clone(),
        );
        write_value(
            &mut values,
            sqrt_rho_over_rn_remainder_name(step),
            step_result.sqrt_rho_over_rn_remainder.clone(),
        );
        write_value(
            &mut values,
            sqrt_rho_over_rn_upper_slack_name(step),
            step_result.sqrt_rho_over_rn_upper_slack.clone(),
        );
        write_nonnegative_bound_support(
            &mut values,
            sqrt_rho_over_rn_signal_name(step),
            &step_result.sqrt_rho_over_rn_fp,
            &sqrt_rho_over_rn_bound(),
            &format!("step_{step}_sqrt_rho_over_rn_sqrt_bound"),
        )?;

        write_value(
            &mut values,
            heating_factor_signal_name(step),
            step_result.heating_factor.clone(),
        );
        write_value(
            &mut values,
            heating_factor_remainder_name(step),
            step_result.heating_factor_remainder.clone(),
        );
        write_value(
            &mut values,
            heating_factor_slack_name(step),
            step_result.heating_factor_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_heating_factor"),
            &step_result.heating_factor_slack,
        );
        write_nonnegative_bound_support(
            &mut values,
            heating_factor_signal_name(step),
            &step_result.heating_factor,
            &heating_factor_bound(),
            &format!("step_{step}_heating_factor_bound"),
        )?;

        write_nonnegative_bound_support(
            &mut values,
            q_dot_signal_name(step),
            &step_result.q_dot_i,
            &q_dot_max_bound(),
            &format!("step_{step}_q_dot_bound"),
        )?;
        write_value(
            &mut values,
            q_dot_remainder_name(step),
            step_result.q_dot_remainder.clone(),
        );
        write_value(
            &mut values,
            q_dot_slack_name(step),
            step_result.q_dot_slack.clone(),
        );
        write_exact_division_slack_anchor(
            &mut values,
            &format!("step_{step}_q_dot"),
            &step_result.q_dot_slack,
        );

        // Write safety envelope slacks
        write_value(
            &mut values,
            q_safety_slack_name(step),
            step_result.q_safety_slack.clone(),
        );
        values.insert(
            nonlinear_anchor_name(&q_safety_slack_name(step)),
            field_square(&step_result.q_safety_slack),
        );
        write_value(
            &mut values,
            q_dot_safety_slack_name(step),
            step_result.q_dot_safety_slack.clone(),
        );
        values.insert(
            nonlinear_anchor_name(&q_dot_safety_slack_name(step)),
            field_square(&step_result.q_dot_safety_slack),
        );
        write_value(
            &mut values,
            h_safety_slack_signal_name(step),
            step_result.h_safety_slack.clone(),
        );
        values.insert(
            nonlinear_anchor_name(&h_safety_slack_signal_name(step)),
            field_square(&step_result.h_safety_slack),
        );
        write_value(
            &mut values,
            v_safety_slack_signal_name(step),
            step_result.v_safety_slack.clone(),
        );
        values.insert(
            nonlinear_anchor_name(&v_safety_slack_signal_name(step)),
            field_square(&step_result.v_safety_slack),
        );

        q_values.push(step_result.q_i.clone());
        q_dot_values.push(step_result.q_dot_i.clone());

        current_h = step_result.next_altitude.clone();
        current_v = step_result.next_velocity.clone();
        current_gamma = step_result.next_gamma.clone();

        altitudes.push(current_h.clone());
        velocities.push(current_v.clone());
        gammas.push(current_gamma.clone());
    }

    // Write running max q support
    let mut max_q = q_values[0].clone();
    write_nonnegative_bound_support(
        &mut values,
        running_max_q_name(0),
        &max_q,
        &dynamic_pressure_bound(),
        "state_0_running_max_q_bound",
    )?;

    for step in 1..steps {
        let next_max = if q_values[step] > max_q {
            q_values[step].clone()
        } else {
            max_q.clone()
        };
        let prev_slack = &next_max - &max_q;
        let curr_slack = &next_max - &q_values[step];
        write_nonnegative_bound_support(
            &mut values,
            running_max_q_name(step),
            &next_max,
            &dynamic_pressure_bound(),
            &format!("state_{step}_running_max_q_bound"),
        )?;
        write_value(&mut values, running_max_q_prev_slack_name(step), prev_slack);
        write_value(&mut values, running_max_q_curr_slack_name(step), curr_slack);
        max_q = next_max;
    }

    // Write running max q_dot support
    let mut max_q_dot = q_dot_values[0].clone();
    write_nonnegative_bound_support(
        &mut values,
        running_max_q_dot_name(0),
        &max_q_dot,
        &q_dot_max_bound(),
        "state_0_running_max_q_dot_bound",
    )?;

    for step in 1..steps {
        let next_max = if q_dot_values[step] > max_q_dot {
            q_dot_values[step].clone()
        } else {
            max_q_dot.clone()
        };
        let prev_slack = &next_max - &max_q_dot;
        let curr_slack = &next_max - &q_dot_values[step];
        write_nonnegative_bound_support(
            &mut values,
            running_max_q_dot_name(step),
            &next_max,
            &q_dot_max_bound(),
            &format!("state_{step}_running_max_q_dot_bound"),
        )?;
        write_value(
            &mut values,
            running_max_q_dot_prev_slack_name(step),
            prev_slack,
        );
        write_value(
            &mut values,
            running_max_q_dot_curr_slack_name(step),
            curr_slack,
        );
        max_q_dot = next_max;
    }

    // Write peak q and peak q_dot public outputs
    write_nonnegative_bound_support(
        &mut values,
        peak_q_output_name(),
        &max_q,
        &dynamic_pressure_bound(),
        "peak_q_public_bound",
    )?;
    write_nonnegative_bound_support(
        &mut values,
        peak_q_dot_output_name(),
        &max_q_dot,
        &q_dot_max_bound(),
        "peak_q_dot_public_bound",
    )?;

    // Trajectory Poseidon commitment
    let mut previous_digest = field_ref(&trajectory_seed_tag());
    for step in 0..=steps {
        let step_index = BigInt::from(step as u64);
        let state_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_state"),
            poseidon_permutation4_reentry([
                &altitudes[step],
                &velocities[step],
                &gammas[step],
                &step_index,
            ])?,
        );
        let previous_digest_bigint = previous_digest.as_bigint();
        let chain_tag = trajectory_step_tag(step);
        let zero_lane = zero();
        previous_digest = write_hash_lanes(
            &mut values,
            &format!("trajectory_step_{step}_chain"),
            poseidon_permutation4_reentry([
                &state_digest.as_bigint(),
                &previous_digest_bigint,
                &chain_tag,
                &zero_lane,
            ])?,
        );
    }
    values.insert(
        trajectory_commitment_output_name().to_string(),
        previous_digest,
    );

    // Terminal state commitment
    let terminal_tag = terminal_state_tag();
    let terminal_digest = write_hash_lanes(
        &mut values,
        "terminal_state_commitment",
        poseidon_permutation4_reentry([
            &altitudes[steps],
            &velocities[steps],
            &gammas[steps],
            &terminal_tag,
        ])?,
    );
    values.insert(
        terminal_state_commitment_output_name().to_string(),
        terminal_digest,
    );

    // Constraint satisfaction
    values.insert(
        constraint_satisfaction_output_name().to_string(),
        FieldElement::ONE,
    );

    Ok(Witness { values })
}

pub fn private_reentry_thermal_witness(inputs: &WitnessInputs) -> ZkfResult<Witness> {
    private_reentry_thermal_witness_with_steps(inputs, PRIVATE_REENTRY_THERMAL_DEFAULT_STEPS)
}

#[doc(hidden)]
pub fn private_reentry_thermal_witness_with_steps(
    inputs: &WitnessInputs,
    steps: usize,
) -> ZkfResult<Witness> {
    stacker::maybe_grow(STACK_GROW_RED_ZONE, STACK_GROW_SIZE, || {
        private_reentry_thermal_witness_inner(inputs, steps)
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::{Value, json};
    use std::panic;
    use std::thread;
    use zkf_backends::blackbox_gadgets::enrich_witness_for_proving;
    use zkf_core::{BackendKind, CompiledProgram, Program, check_constraints};

    const REENTRY_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_reentry_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(REENTRY_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn lowered_compiled_program_for_test(program: &Program) -> CompiledProgram {
        let lowered =
            zkf_backends::lower_program_for_backend(program, BackendKind::Plonky3).expect("lower");
        let mut compiled = CompiledProgram::new(BackendKind::Plonky3, lowered.program);
        if program.digest_hex() != compiled.program.digest_hex() {
            compiled.original_program = Some(program.clone());
        }
        compiled
    }

    fn prepared_witness_for_test(
        template: &TemplateProgram,
        witness: &Witness,
    ) -> (CompiledProgram, Witness) {
        let compiled = lowered_compiled_program_for_test(&template.program);
        let prepared = enrich_witness_for_proving(&compiled, witness).expect("prepared witness");
        (compiled, prepared)
    }

    fn atmosphere_band_row_value(row: &ReentryAtmosphereBandRowV1) -> Value {
        json!({
            "altitude_start": row.altitude_start,
            "altitude_end": row.altitude_end,
            "density_start": row.density_start,
            "density_end": row.density_end,
        })
    }

    fn sine_band_row_value(row: &ReentrySineBandRowV1) -> Value {
        json!({
            "gamma_start": row.gamma_start,
            "gamma_end": row.gamma_end,
            "sine_start": row.sine_start,
            "sine_end": row.sine_end,
        })
    }

    fn abort_corridor_band_row_value(row: &ReentryAbortCorridorBandRowV1) -> Value {
        json!({
            "altitude_start": row.altitude_start,
            "altitude_end": row.altitude_end,
            "velocity_min": row.velocity_min,
            "velocity_max": row.velocity_max,
            "gamma_min": row.gamma_min,
            "gamma_max": row.gamma_max,
        })
    }

    fn public_key_bundle_value(bundle: &PublicKeyBundle) -> Value {
        json!({
            "scheme": bundle.scheme,
            "ed25519": bundle.ed25519,
            "ml_dsa87": bundle.ml_dsa87,
        })
    }

    fn signature_bundle_value(bundle: &SignatureBundle) -> Value {
        json!({
            "scheme": bundle.scheme,
            "ed25519": bundle.ed25519,
            "ml_dsa87": bundle.ml_dsa87,
        })
    }

    fn mission_pack_v2_value(mission_pack: &ReentryMissionPackV2) -> Value {
        json!({
            "private": {
                "initial_altitude": mission_pack.private.initial_altitude,
                "initial_velocity": mission_pack.private.initial_velocity,
                "initial_flight_path_angle": mission_pack.private.initial_flight_path_angle,
                "vehicle_mass": mission_pack.private.vehicle_mass,
                "reference_area": mission_pack.private.reference_area,
                "drag_coefficient": mission_pack.private.drag_coefficient,
                "lift_coefficient": mission_pack.private.lift_coefficient,
                "nose_radius": mission_pack.private.nose_radius,
                "bank_angle_cosines": mission_pack.private.bank_angle_cosines,
                "atmosphere_bands": mission_pack
                    .private
                    .atmosphere_bands
                    .iter()
                    .map(atmosphere_band_row_value)
                    .collect::<Vec<_>>(),
                "sine_bands": mission_pack
                    .private
                    .sine_bands
                    .iter()
                    .map(sine_band_row_value)
                    .collect::<Vec<_>>(),
                "abort_thresholds": {
                    "q_trigger_min": mission_pack.private.abort_thresholds.q_trigger_min,
                    "q_dot_trigger_min": mission_pack.private.abort_thresholds.q_dot_trigger_min,
                    "altitude_floor": mission_pack.private.abort_thresholds.altitude_floor,
                    "velocity_ceiling": mission_pack.private.abort_thresholds.velocity_ceiling,
                },
                "abort_corridor_bands": mission_pack
                    .private
                    .abort_corridor_bands
                    .iter()
                    .map(abort_corridor_band_row_value)
                    .collect::<Vec<_>>(),
            },
            "public_envelope": {
                "q_max": mission_pack.public_envelope.q_max,
                "q_dot_max": mission_pack.public_envelope.q_dot_max,
                "h_min": mission_pack.public_envelope.h_min,
                "v_max": mission_pack.public_envelope.v_max,
                "gamma_bound": mission_pack.public_envelope.gamma_bound,
                "g_0": mission_pack.public_envelope.g_0,
                "k_sg": mission_pack.public_envelope.k_sg,
                "certified_horizon_steps": mission_pack.public_envelope.certified_horizon_steps,
            },
            "private_model_commitments": {
                "mission_id": mission_pack.private_model_commitments.mission_id,
                "aerodynamic_model_commitment": mission_pack
                    .private_model_commitments
                    .aerodynamic_model_commitment,
                "thermal_model_commitment": mission_pack
                    .private_model_commitments
                    .thermal_model_commitment,
                "guidance_policy_commitment": mission_pack
                    .private_model_commitments
                    .guidance_policy_commitment,
            },
            "provenance_metadata": mission_pack.provenance_metadata,
        })
    }

    fn sample_public_key_bundle() -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: vec![1, 2, 3, 4],
            ml_dsa87: vec![5, 6, 7, 8],
        }
    }

    fn sample_signature_bundle() -> SignatureBundle {
        SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: vec![9, 10, 11, 12],
            ml_dsa87: vec![13, 14, 15, 16],
        }
    }

    fn sample_signed_reentry_mission_pack_v1() -> SignedReentryMissionPackV1 {
        let payload = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        let payload_digest = reentry_mission_pack_v2_digest(&payload).expect("payload digest");
        SignedReentryMissionPackV1 {
            payload,
            payload_digest,
            signer_identity: "flight-authority".to_string(),
            signer_public_keys: sample_public_key_bundle(),
            signer_signature_bundle: sample_signature_bundle(),
            not_before_unix_epoch_seconds: 0,
            not_after_unix_epoch_seconds: 4_000_000_000,
            provenance_metadata: BTreeMap::from([
                (
                    "signature_bundle".to_string(),
                    "hybrid-ed25519-ml-dsa-44".to_string(),
                ),
                ("authority".to_string(), "schema-freeze-test".to_string()),
            ]),
        }
    }

    fn sample_reentry_signer_manifest_v1() -> ReentrySignerManifestV1 {
        let signed_pack = sample_signed_reentry_mission_pack_v1();
        ReentrySignerManifestV1 {
            version: 1,
            manifest_id: "reentry-schema-freeze-manifest".to_string(),
            authorized_signers: vec![ReentryAuthorizedSignerV1 {
                signer_identity: signed_pack.signer_identity,
                public_keys: signed_pack.signer_public_keys,
                not_before_unix_epoch_seconds: Some(0),
                not_after_unix_epoch_seconds: Some(4_000_000_000),
                metadata: BTreeMap::from([
                    ("purpose".to_string(), "schema-freeze".to_string()),
                    ("environment".to_string(), "test".to_string()),
                ]),
            }],
            metadata: BTreeMap::from([
                ("environment".to_string(), "test".to_string()),
                ("owner".to_string(), "reentry-schema-freeze".to_string()),
            ]),
        }
    }

    fn sample_reentry_assurance_receipt_v2() -> ReentryAssuranceReceiptV2 {
        let signed_pack = sample_signed_reentry_mission_pack_v1();
        let signer_manifest = sample_reentry_signer_manifest_v1();
        let witness =
            private_reentry_thermal_accepted_witness_from_mission_pack(&signed_pack.payload)
                .expect("accepted witness");
        build_reentry_assurance_receipt_v2(&signed_pack, &signer_manifest, &witness, "plonky3")
            .expect("receipt")
    }

    fn sample_reentry_oracle_summary_v1() -> ReentryOracleSummaryV1 {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        build_reentry_oracle_summary_v1(&mission_pack).expect("oracle")
    }

    fn assert_unknown_field_rejected<T>(value: Value)
    where
        T: DeserializeOwned + std::fmt::Debug,
    {
        let mut object = value.as_object().cloned().expect("schema value object");
        object.insert("schema_drift".to_string(), json!(true));
        let error =
            serde_json::from_value::<T>(Value::Object(object)).expect_err("unknown field rejected");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected serde error: {error}"
        );
    }

    #[test]
    fn reentry_template_has_expected_surface() {
        let steps = 2;
        let template = private_reentry_thermal_showcase_with_steps(steps).expect("template");
        assert_eq!(
            template.expected_inputs.len(),
            PRIVATE_REENTRY_THERMAL_PUBLIC_INPUTS + private_input_count_for_steps(steps)
        );
        assert_eq!(
            template.public_outputs.len(),
            PRIVATE_REENTRY_THERMAL_PUBLIC_OUTPUTS
        );
        assert_eq!(
            template
                .program
                .metadata
                .get("integration_steps")
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            template
                .program
                .metadata
                .get("integrator")
                .map(String::as_str),
            Some("euler")
        );
    }

    #[test]
    fn reentry_small_step_witness_satisfies_constraints() {
        run_reentry_test_on_large_stack("reentry_small_step_witness_satisfies_constraints", || {
            for steps in 1..=2 {
                let template =
                    private_reentry_thermal_showcase_with_steps(steps).expect("template");
                let compiled = lowered_compiled_program_for_test(&template.program);
                let witness =
                    private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
                        .expect("witness");
                let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
                if let Err(error) = check_constraints(&compiled.program, &prepared) {
                    let failing_constraint = match &error {
                        zkf_core::ZkfError::ConstraintViolation { index, .. }
                        | zkf_core::ZkfError::BooleanConstraintViolation { index, .. }
                        | zkf_core::ZkfError::RangeConstraintViolation { index, .. }
                        | zkf_core::ZkfError::LookupConstraintViolation { index, .. } => compiled
                            .program
                            .constraints
                            .get(*index)
                            .map(|constraint| format!("{constraint:?}"))
                            .unwrap_or_else(|| "<missing constraint>".to_string()),
                        _ => "<non-constraint error>".to_string(),
                    };
                    panic!(
                        "constraints failed for steps={steps}: {error:?}\nfailing_constraint={failing_constraint}"
                    );
                }
            }
        });
    }

    #[test]
    fn reentry_zero_mass_fails() {
        let mut inputs = reentry_sample_inputs_for_steps(2);
        inputs.insert(mass_input_name().to_string(), field(zero()));
        private_reentry_thermal_witness_with_steps(&inputs, 2).expect_err("zero mass must fail");
    }

    #[test]
    fn reentry_request_step_mismatch_fails() {
        let request = PrivateReentryThermalRequestV1 {
            private: ReentryPrivateInputsV1 {
                initial_altitude: "80".to_string(),
                initial_velocity: "7".to_string(),
                initial_flight_path_angle: "-0.02".to_string(),
                vehicle_mass: "10".to_string(),
                reference_area: "10".to_string(),
                drag_coefficient: "1.5".to_string(),
                lift_coefficient: "0.5".to_string(),
                nose_radius: "1".to_string(),
                bank_angle_cosines: vec!["0.5".to_string()],
                sin_gamma: vec!["-0.02".to_string()],
                cos_gamma: vec!["0.9998".to_string()],
                density_profile: vec!["0.00001".to_string()],
            },
            public: ReentryPublicInputsV1 {
                q_max: "500".to_string(),
                q_dot_max: "200".to_string(),
                h_min: "30".to_string(),
                v_max: "7.8".to_string(),
                gamma_bound: "0.35".to_string(),
                g_0: "0.009806".to_string(),
                k_sg: "0.0001".to_string(),
                step_count: 2,
            },
        };
        WitnessInputs::try_from(request).expect_err("step-count mismatch must fail");
    }

    #[test]
    fn reentry_public_commitments_present_in_witness() {
        run_reentry_test_on_large_stack("reentry_public_commitments_present_in_witness", || {
            let steps = 2;
            let template = private_reentry_thermal_showcase_with_steps(steps).expect("template");
            let witness =
                private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
                    .expect("witness");
            assert!(
                witness
                    .values
                    .contains_key(trajectory_commitment_output_name())
            );
            assert!(
                witness
                    .values
                    .contains_key(terminal_state_commitment_output_name())
            );
            assert_eq!(
                witness.values[constraint_satisfaction_output_name()],
                FieldElement::ONE
            );
            assert!(witness.values.contains_key(peak_q_output_name()));
            assert!(witness.values.contains_key(peak_q_dot_output_name()));
        });
    }

    #[test]
    fn reentry_tampered_heating_rate_fails_constraints() {
        let steps = 2;
        let template = private_reentry_thermal_showcase_with_steps(steps).expect("template");
        let mut witness =
            private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
                .expect("witness");
        let signal = q_dot_signal_name(0);
        let tampered = witness.values[&signal].as_bigint() + one();
        witness.values.insert(signal, field(tampered));
        let (compiled, prepared) = prepared_witness_for_test(&template, &witness);
        check_constraints(&compiled.program, &prepared)
            .expect_err("tampered heating-rate witness must fail");
    }

    #[test]
    fn reentry_tampered_sqrt_support_fails_constraints() {
        let steps = 2;
        let template = private_reentry_thermal_showcase_with_steps(steps).expect("template");
        let mut witness =
            private_reentry_thermal_witness_with_steps(&template.sample_inputs, steps)
                .expect("witness");
        let signal = sqrt_rho_over_rn_signal_name(0);
        let tampered = witness.values[&signal].as_bigint() + one();
        witness.values.insert(signal, field(tampered));
        let (compiled, prepared) = prepared_witness_for_test(&template, &witness);
        check_constraints(&compiled.program, &prepared)
            .expect_err("tampered sqrt support witness must fail");
    }

    #[test]
    fn reentry_receipt_projects_theorem_lane_outputs() {
        let mission_pack = reentry_mission_pack_sample_with_steps(2).expect("mission pack");
        let request: PrivateReentryThermalRequestV1 = mission_pack.clone().into();
        let inputs = WitnessInputs::try_from(request).expect("inputs");
        let witness = private_reentry_thermal_witness_with_steps(&inputs, 2).expect("witness");
        let receipt =
            build_reentry_assurance_receipt(&mission_pack, &witness, "plonky3").expect("receipt");
        assert_eq!(receipt.backend, "plonky3");
        assert_eq!(receipt.theorem_lane, "transparent-fixed-policy-cpu");
        assert_eq!(receipt.horizon_steps, 2);
        assert!(receipt.compliance_bit);
        assert!(!receipt.mission_pack_digest.is_empty());
        assert!(receipt.mathematical_model.contains("explicit-Euler"));
        assert!(!receipt.theorem_hypotheses.is_empty());
        assert!(!receipt.trajectory_commitment.is_empty());
        assert!(!receipt.terminal_state_commitment.is_empty());
    }

    #[test]
    fn reentry_v2_materialization_generates_valid_request() {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack v2");
        let request =
            materialize_private_reentry_request_v1_from_v2(&mission_pack).expect("materialized");
        let inputs = WitnessInputs::try_from(request.clone()).expect("inputs");
        let witness =
            private_reentry_thermal_witness_with_steps(&inputs, request.public.step_count)
                .expect("witness");
        assert_eq!(request.private.density_profile.len(), 2);
        assert_eq!(request.private.sin_gamma.len(), 2);
        assert_eq!(request.private.cos_gamma.len(), 2);
        assert_eq!(
            witness.values[constraint_satisfaction_output_name()],
            FieldElement::ONE
        );
    }

    #[test]
    fn reentry_v2_abort_thresholds_fail_closed() {
        let mut mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        mission_pack.private.abort_thresholds.velocity_ceiling = "0.1".to_string();
        materialize_private_reentry_request_v1_from_v2(&mission_pack)
            .expect_err("abort-triggering mission packs must fail closed");
    }

    #[test]
    fn reentry_mission_pack_v2_schema_is_frozen() {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        assert_eq!(
            serde_json::to_value(&mission_pack).expect("serialize"),
            mission_pack_v2_value(&mission_pack)
        );
        assert_unknown_field_rejected::<ReentryMissionPackV2>(mission_pack_v2_value(&mission_pack));
    }

    #[test]
    fn signed_reentry_mission_pack_v1_schema_is_frozen() {
        let signed_pack = sample_signed_reentry_mission_pack_v1();
        let expected = json!({
            "payload": mission_pack_v2_value(&signed_pack.payload),
            "payload_digest": signed_pack.payload_digest,
            "signer_identity": signed_pack.signer_identity,
            "signer_public_keys": public_key_bundle_value(&signed_pack.signer_public_keys),
            "signer_signature_bundle": signature_bundle_value(&signed_pack.signer_signature_bundle),
            "not_before_unix_epoch_seconds": signed_pack.not_before_unix_epoch_seconds,
            "not_after_unix_epoch_seconds": signed_pack.not_after_unix_epoch_seconds,
            "provenance_metadata": signed_pack.provenance_metadata,
        });
        assert_eq!(
            serde_json::to_value(&signed_pack).expect("serialize"),
            expected
        );
        assert_unknown_field_rejected::<SignedReentryMissionPackV1>(expected);
    }

    #[test]
    fn reentry_signer_manifest_v1_schema_is_frozen() {
        let manifest = sample_reentry_signer_manifest_v1();
        let expected = json!({
            "version": manifest.version,
            "manifest_id": manifest.manifest_id,
            "authorized_signers": manifest
                .authorized_signers
                .iter()
                .map(|signer| json!({
                    "signer_identity": signer.signer_identity,
                    "public_keys": public_key_bundle_value(&signer.public_keys),
                    "not_before_unix_epoch_seconds": signer.not_before_unix_epoch_seconds,
                    "not_after_unix_epoch_seconds": signer.not_after_unix_epoch_seconds,
                    "metadata": signer.metadata,
                }))
                .collect::<Vec<_>>(),
            "metadata": manifest.metadata,
        });
        assert_eq!(
            serde_json::to_value(&manifest).expect("serialize"),
            expected
        );
        assert_unknown_field_rejected::<ReentrySignerManifestV1>(expected);
    }

    #[test]
    fn reentry_assurance_receipt_v2_schema_is_frozen() {
        let receipt = sample_reentry_assurance_receipt_v2();
        let expected = json!({
            "mission_id": receipt.mission_id,
            "mission_pack_digest": receipt.mission_pack_digest,
            "signer_manifest_digest": receipt.signer_manifest_digest,
            "signer_identity": receipt.signer_identity,
            "backend": receipt.backend,
            "theorem_lane": receipt.theorem_lane,
            "model_revision": receipt.model_revision,
            "mathematical_model": receipt.mathematical_model,
            "theorem_hypotheses": receipt.theorem_hypotheses,
            "horizon_steps": receipt.horizon_steps,
            "fixed_point_scale": receipt.fixed_point_scale,
            "trajectory_commitment": receipt.trajectory_commitment,
            "terminal_state_commitment": receipt.terminal_state_commitment,
            "peak_dynamic_pressure": receipt.peak_dynamic_pressure,
            "peak_heating_rate": receipt.peak_heating_rate,
            "compliance_bit": receipt.compliance_bit,
            "minimal_tcb": receipt.minimal_tcb,
        });
        assert_eq!(serde_json::to_value(&receipt).expect("serialize"), expected);
        assert_unknown_field_rejected::<ReentryAssuranceReceiptV2>(expected);
    }

    #[test]
    fn reentry_oracle_summary_matches_receipt_public_metrics() {
        let signed_pack = sample_signed_reentry_mission_pack_v1();
        let signer_manifest = sample_reentry_signer_manifest_v1();
        let witness =
            private_reentry_thermal_accepted_witness_from_mission_pack(&signed_pack.payload)
                .expect("accepted witness");
        let receipt =
            build_reentry_assurance_receipt_v2(&signed_pack, &signer_manifest, &witness, "plonky3")
                .expect("receipt");
        let oracle = build_reentry_oracle_summary_v1(&signed_pack.payload).expect("oracle");
        let comparison = compare_reentry_receipt_to_oracle_v1(&receipt, &oracle);
        assert!(
            comparison.matched,
            "oracle mismatches: {:?}",
            comparison.mismatches
        );
        assert_eq!(oracle.peak_dynamic_pressure, receipt.peak_dynamic_pressure);
        assert_eq!(oracle.peak_heating_rate, receipt.peak_heating_rate);
        assert_eq!(oracle.compliance_bit, receipt.compliance_bit);
        assert_eq!(oracle.horizon_steps, receipt.horizon_steps);
    }

    #[test]
    fn reentry_oracle_summary_v1_schema_is_frozen() {
        let oracle = sample_reentry_oracle_summary_v1();
        let expected = json!({
            "mission_id": oracle.mission_id,
            "mission_pack_digest": oracle.mission_pack_digest,
            "oracle_lane": oracle.oracle_lane,
            "model_revision": oracle.model_revision,
            "horizon_steps": oracle.horizon_steps,
            "fixed_point_scale": oracle.fixed_point_scale,
            "peak_dynamic_pressure": oracle.peak_dynamic_pressure,
            "peak_heating_rate": oracle.peak_heating_rate,
            "compliance_bit": oracle.compliance_bit,
        });
        assert_eq!(serde_json::to_value(&oracle).expect("serialize"), expected);
        assert_unknown_field_rejected::<ReentryOracleSummaryV1>(expected);
    }

    #[test]
    fn accepted_rk4_sample_path_stays_nominal() {
        let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        let steps = simulate_reentry_rk4_path_from_v2(&mission_pack).expect("accepted rk4 path");
        assert_eq!(steps.len(), 2);
        assert!(steps.iter().all(|step| !step.abort_triggered));
        assert!(steps.iter().all(|step| !step.next_abort_latch));
        assert!(steps[0].stage_q_max >= zero());
        assert!(steps[0].stage_q_dot_max >= zero());
    }

    #[test]
    fn accepted_rk4_abort_latch_triggers_and_sticks() {
        let mut mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
        mission_pack.private.abort_thresholds.velocity_ceiling = "6.5".to_string();
        let steps = simulate_reentry_rk4_path_from_v2(&mission_pack).expect("accepted rk4 path");
        assert_eq!(steps.len(), 2);
        assert!(steps[0].abort_triggered);
        assert!(steps[0].next_abort_latch);
        assert!(steps[1].current_abort_latch);
        assert!(steps[1].next_abort_latch);
    }

    #[test]
    fn accepted_rk4_program_and_witness_satisfy_constraints() {
        run_reentry_test_on_large_stack(
            "accepted_rk4_program_and_witness_satisfy_constraints",
            || {
                let mission_pack =
                    reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
                let program =
                    build_private_reentry_thermal_accepted_program_for_mission_pack(&mission_pack)
                        .expect("accepted program");
                let compiled = lowered_compiled_program_for_test(&program);
                let witness =
                    private_reentry_thermal_accepted_witness_from_mission_pack(&mission_pack)
                        .expect("accepted witness");
                let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
                if let Err(error) = check_constraints(&compiled.program, &prepared) {
                    let failing_constraint = match &error {
                        zkf_core::ZkfError::ConstraintViolation { index, .. }
                        | zkf_core::ZkfError::BooleanConstraintViolation { index, .. }
                        | zkf_core::ZkfError::RangeConstraintViolation { index, .. }
                        | zkf_core::ZkfError::LookupConstraintViolation { index, .. } => compiled
                            .program
                            .constraints
                            .get(*index)
                            .map(|constraint| format!("{constraint:?}"))
                            .unwrap_or_else(|| "<missing constraint>".to_string()),
                        _ => "<non-constraint error>".to_string(),
                    };
                    panic!(
                        "accepted constraints failed: {error:?}\nfailing_constraint={failing_constraint}"
                    );
                }
            },
        );
    }

    #[test]
    fn accepted_rk4_tampered_rho_fails_constraints() {
        run_reentry_test_on_large_stack("accepted_rk4_tampered_rho_fails_constraints", || {
            let mission_pack = reentry_mission_pack_v2_sample_with_steps(2).expect("mission pack");
            let program =
                build_private_reentry_thermal_accepted_program_for_mission_pack(&mission_pack)
                    .expect("accepted program");
            let mut witness =
                private_reentry_thermal_accepted_witness_from_mission_pack(&mission_pack)
                    .expect("accepted witness");
            let signal = accepted_stage_rho_name(0, 1);
            let tampered = witness.values[&signal].as_bigint() + one();
            witness.values.insert(signal, field(tampered));
            let compiled = lowered_compiled_program_for_test(&program);
            let prepared = enrich_witness_for_proving(&compiled, &witness).expect("prepared");
            check_constraints(&compiled.program, &prepared)
                .expect_err("tampered accepted rho witness must fail");
        });
    }
}
