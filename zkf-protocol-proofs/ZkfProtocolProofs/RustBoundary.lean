import ZkfProtocolProofs.GeneratedSnapshots
import ZkfProtocolProofs.Groth16Exact
import ZkfProtocolProofs.FriExact
import ZkfProtocolProofs.NovaExact
import ZkfProtocolProofs.HyperNovaExact

namespace ZkfProtocolProofs

def trackedRustFiles : List RustFileSnapshot :=
  groth16Snapshot.rustFiles ++ friSnapshot.rustFiles ++ novaSnapshot.rustFiles

theorem trackedRustFiles_count : trackedRustFiles.length = 5 := rfl

theorem trackedRustFile_paths :
    trackedRustFiles.map RustFileSnapshot.path =
      [
        "zkf-backends/src/arkworks.rs",
        "zkf-backends/src/lib_non_hax.rs",
        "zkf-backends/src/plonky3.rs",
        "zkf-backends/src/wrapping/stark_to_groth16.rs",
        "zkf-backends/src/nova_native.rs"
      ] := rfl

theorem groth16_rust_surface_tracks_arkworks :
    groth16ExactSurface.rustFiles.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/arkworks.rs" := rfl

theorem groth16_rust_surface_tracks_boundary_helpers :
    groth16ExactSurface.rustFiles.reverse.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/lib_non_hax.rs" := rfl

theorem fri_rust_surface_tracks_native_backend :
    friExactTranscriptSurface.rustFiles.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/plonky3.rs" := rfl

theorem fri_rust_surface_tracks_wrapper :
    friExactTranscriptSurface.rustFiles.reverse.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/wrapping/stark_to_groth16.rs" := rfl

theorem nova_rust_surface_tracks_native_backend :
    classicNovaExactSurface.rustFiles.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/nova_native.rs" := rfl

theorem hypernova_rust_surface_tracks_native_backend :
    hyperNovaExactSurface.rustFiles.head?.map RustFileSnapshot.path =
      some "zkf-backends/src/nova_native.rs" := rfl

theorem all_protocol_surfaces_share_five_tracked_files :
    groth16ExactSurface.rustFiles.length +
      friExactTranscriptSurface.rustFiles.length +
      classicNovaExactSurface.rustFiles.length = trackedRustFiles.length := rfl

end ZkfProtocolProofs
