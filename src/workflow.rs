//! A thin workflow wrapping `sendCoa`, so the activity can be exercised from the `temporal` CLI
//! (or any client) without a separate workflow worker.

use std::time::Duration;

use temporalio_common::RetryPolicy;
use temporalio_macros::{workflow, workflow_methods};
use temporalio_sdk::{ActivityOptions, WorkflowContext, WorkflowResult};

use crate::{
    activities::RadiusActivities,
    coa::{CoaRequest, CoaResult},
};

#[workflow]
#[derive(Default)]
pub struct SendCoaWorkflow;

#[workflow_methods]
impl SendCoaWorkflow {
    #[run]
    pub async fn run(ctx: &mut WorkflowContext<Self>, req: CoaRequest) -> WorkflowResult<CoaResult> {
        let mut opts = ActivityOptions::start_to_close_timeout(Duration::from_secs(60));
        opts.retry_policy = Some(
            RetryPolicy::builder()
                .initial_interval(Duration::from_secs(1))
                .backoff_coefficient(2.0)
                .maximum_interval(Duration::from_secs(30))
                .maximum_attempts(5)
                .build(),
        );
        Ok(ctx.execute_activity(RadiusActivities::send_coa, req, opts).await?)
    }
}
