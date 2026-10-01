use std::sync::Arc;

use temporalio_common::error::ApplicationFailure;
use temporalio_macros::activities;
use temporalio_sdk::activities::{ActivityContext, ActivityError};

use crate::coa::{CoaClient, CoaError, CoaRequest, CoaResult};

pub struct RadiusActivities {
    client: CoaClient,
}

impl RadiusActivities {
    pub fn new(client: CoaClient) -> Self {
        Self { client }
    }
}

#[activities]
impl RadiusActivities {
    /// Sends a CoA-Request (or Disconnect-Request) to a NAS and waits for the ACK/NAK.
    ///
    /// A NAK is a successful activity result (`acked: false`); timeouts and network errors are
    /// retryable failures; invalid input and reply-verification failures are non-retryable.
    #[activity(name = "actRadiusCoa")]
    pub async fn act_radius_coa(
        self: Arc<Self>,
        ctx: ActivityContext,
        req: CoaRequest,
    ) -> Result<CoaResult, ActivityError> {
        let info = ctx.info();
        tracing::info!(
            workflow_id = ?info.workflow_id,
            attempt = info.attempt,
            nas = %req.nas_address,
            kind = ?req.kind,
            "actRadiusCoa"
        );
        match self.client.send(&req).await {
            Ok(res) => {
                tracing::info!(nas = %res.nas, code = ?res.code, attempts = res.attempts, "actRadiusCoa reply");
                Ok(res)
            }
            Err(err) => {
                tracing::warn!("actRadiusCoa failed: {err}");
                Err(ActivityError::application(to_failure(err)))
            }
        }
    }
}

fn to_failure(err: CoaError) -> ApplicationFailure {
    let type_name = match &err {
        CoaError::Invalid(_) => "InvalidCoaRequest",
        CoaError::BadReply { .. } => "CoaReplyVerificationFailed",
        CoaError::Timeout { .. } => "CoaTimeout",
        CoaError::Io { .. } => "CoaNetworkError",
    };
    let retryable = err.is_retryable();
    ApplicationFailure::builder(err).type_name(type_name.to_string()).non_retryable(!retryable).build()
}
