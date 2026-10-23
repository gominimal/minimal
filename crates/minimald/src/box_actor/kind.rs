//! The per-message span name of a [`BoxMessage`]: the variant's name.

use super::BoxMessage;

impl BoxMessage {
    /// The variant's name, for the actor's per-message span.
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::GetPaths { .. } => "GetPaths",
            Self::MakeContext { .. } => "MakeContext",
            Self::Attach { .. } => "Attach",
            Self::EnsureHost { .. } => "EnsureHost",
            Self::GetWorkspaceDelta { .. } => "GetWorkspaceDelta",
            Self::GetHostScreen { .. } => "GetHostScreen",
            Self::ConfigureLoadout { .. } => "ConfigureLoadout",
            Self::SubmitVerdict { .. } => "SubmitVerdict",
            Self::Finalize { .. } => "Finalize",
            Self::RunDetachHooks { .. } => "RunDetachHooks",
            Self::Abort { .. } => "Abort",
            Self::Rename { .. } => "Rename",
            Self::IsBusy { .. } => "IsBusy",
            Self::Stop { .. } => "Stop",
            Self::Destroy { .. } => "Destroy",
            Self::DestroyIfUnfinalized(_) => "DestroyIfUnfinalized",
            Self::GetRecord { .. } => "GetRecord",
            Self::GetNetSwitch { .. } => "GetNetSwitch",
            Self::GetDenyAllOptOut(_) => "GetDenyAllOptOut",
            Self::GetComposition { .. } => "GetComposition",
            Self::GetPatchesUploadLock { .. } => "GetPatchesUploadLock",
            Self::GetHookScriptsUploadLock { .. } => "GetHookScriptsUploadLock",
            Self::TrackForward { .. } => "TrackForward",
            Self::StartBuild { .. } => "StartBuild",
            Self::StartCheck { .. } => "StartCheck",
            Self::StartMaterialize { .. } => "StartMaterialize",
            Self::ExposeDynamic { .. } => "ExposeDynamic",
            Self::LiveIngress { .. } => "LiveIngress",
            Self::AskAnswered { .. } => "AskAnswered",
            #[cfg(target_os = "linux")]
            Self::BindHandedPort { .. } => "BindHandedPort",
            Self::SetWorkspaceUploadInFlight(..) => "SetWorkspaceUploadInFlight",
            #[cfg(test)]
            Self::PeekPendingAsks(_) => "PeekPendingAsks",
            #[cfg(test)]
            Self::Park(..) => "Park",
            #[cfg(test)]
            Self::PeekComposition { .. } => "PeekComposition",
            #[cfg(test)]
            Self::PeekIngressCells(_) => "PeekIngressCells",
            #[cfg(test)]
            Self::CheckPackagesAtFinalize(..) => "CheckPackagesAtFinalize",
            #[cfg(test)]
            Self::ForgetComposedGraphNames(_) => "ForgetComposedGraphNames",
            #[cfg(test)]
            Self::HoldUntil(..) => "HoldUntil",
        }
    }
}
