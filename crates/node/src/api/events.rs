//! The event stream route: server-sent events of the topics a client names.

use axiom_http::{Method, Request, Response, StatusCode};
use axiom_types::Preset;

use super::{
    ApiContext,
    query::Query,
    reply::{ApiError, Routes},
};
use crate::{EventTopic, TopicSet};

/// Media type of a server-sent event stream.
const EVENT_STREAM: &str = "text/event-stream";

/// The route under `/eth/v1/events`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EventRoutes;

impl EventRoutes {
    /// Adds this namespace's route.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes.raw(
            Method::Get,
            "/eth/v1/events",
            |context, request| async move {
                Self::events::<P>(context, request)
                    .await
                    .unwrap_or_else(ApiError::into_response)
            },
        )
    }

    /// Opens a stream of the named topics' events, from now until the client leaves.
    ///
    /// Topics may repeat the parameter or join names with commas; at least one is required.
    async fn events<P: Preset>(
        context: ApiContext<P>,
        request: Request,
    ) -> Result<Response, ApiError> {
        if let Some(accept) = request.headers.get("accept")
            && !accept.contains(EVENT_STREAM)
            && !accept.contains("*/*")
        {
            return Err(ApiError::not_acceptable(false));
        }
        let topics = Self::topics(&Query::of(&request))?;
        let stream = context
            .events
            .subscribe(topics)
            .await
            .map_err(|error| ApiError::unavailable(error.to_string()))?;
        Ok(Response::streaming(StatusCode::OK, EVENT_STREAM, stream)
            .with_header("cache-control", "no-cache"))
    }

    /// The topics a query names.
    fn topics(query: &Query) -> Result<TopicSet, ApiError> {
        let names = query.list("topics");
        if names.is_empty() {
            return Err(ApiError::bad_request("no topics requested"));
        }
        names
            .into_iter()
            .map(|name| {
                name.parse::<EventTopic>()
                    .map_err(|error| ApiError::bad_request(error.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topics(target: &str) -> Result<TopicSet, ApiError> {
        EventRoutes::topics(&Query::of(&Request::new(Method::Get, target)))
    }

    #[test]
    fn topics_are_named_by_list() {
        // Two topics joined by a comma, and a third repeated.
        assert_eq!(
            topics("/eth/v1/events?topics=head,block&topics=chain_reorg"),
            Ok(TopicSet::EMPTY
                .with(EventTopic::Head)
                .with(EventTopic::Block)
                .with(EventTopic::ChainReorg))
        );

        // None at all, and an unknown name, are both bad requests.
        assert_eq!(
            topics("/eth/v1/events"),
            Err(ApiError::bad_request("no topics requested"))
        );
        assert_eq!(
            topics("/eth/v1/events?topics=head,heads"),
            Err(ApiError::bad_request("unknown event topic: heads"))
        );
    }
}
