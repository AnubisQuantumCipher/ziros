pub mod manifest;
pub mod registry;
pub mod resolver;

pub use manifest::GadgetManifest;
pub use registry::{CombinedRegistry, LocalRegistry, RemoteRegistry};
pub use resolver::{VersionReq, resolve_dependencies};
