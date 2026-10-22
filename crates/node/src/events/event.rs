//! One event of the beacon API's event stream, and its wire form.

use axiom_beacon_json::ApiJson;
use axiom_json::{Json, Object};
use axiom_types::ForkName;

use super::EventTopic;

/// One event, ready to fan out to every subscriber of its topic.
///
/// Producers build an event only when some client wants its topic, so its JSON is made eagerly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiEvent {
    /// The topic subscribers chose.
    topic: EventTopic,
    /// The data line's value.
    data: Json,
}

impl ApiEvent {
    /// An event whose data the producer built as JSON.
    #[must_use]
    pub const fn json(topic: EventTopic, data: Json) -> Self {
        Self { topic, data }
    }

    /// An event carrying a consensus object, as its JSON form.
    #[must_use]
    pub fn object<T: ApiJson>(topic: EventTopic, value: &T) -> Self {
        Self::json(topic, value.to_json())
    }

    /// An event carrying data of a fork, wrapped with the fork's name.
    #[must_use]
    pub fn versioned(topic: EventTopic, fork: ForkName, data: Json) -> Self {
        let mut object = Object::new();
        object.insert("version", Json::from(fork.to_string()));
        object.insert("data", data);
        Self::json(topic, Json::Object(object))
    }

    /// The event's topic.
    #[must_use]
    pub const fn topic(&self) -> EventTopic {
        self.topic
    }

    /// The event in the server-sent events format: a name line, a data line, a blank line.
    ///
    /// The JSON is compact, so it holds no line break that would split the data field.
    /// See the event stream format of the HTML living standard.
    #[must_use]
    pub fn render(&self) -> Vec<u8> {
        format!("event: {}\ndata: {}\n\n", self.topic, self.data).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Epoch, ValidatorIndex, phase0::VoluntaryExit};

    use super::*;

    #[test]
    fn events_render_as_one_named_data_line() {
        // A built object: the finalized checkpoint summary.
        let event = ApiEvent::json(
            EventTopic::FinalizedCheckpoint,
            Json::from([("epoch", Json::from("2"))]),
        );
        assert_eq!(
            event.render(),
            b"event: finalized_checkpoint\ndata: {\"epoch\":\"2\"}\n\n".to_vec()
        );

        // A consensus object, in its beacon API form.
        let exit = VoluntaryExit {
            epoch: Epoch(1),
            validator_index: ValidatorIndex(7),
        };
        assert_eq!(
            ApiEvent::object(EventTopic::VoluntaryExit, &exit).render(),
            b"event: voluntary_exit\ndata: {\"epoch\":\"1\",\"validator_index\":\"7\"}\n\n"
                .to_vec()
        );

        // Versioned data names its fork beside the data.
        let event = ApiEvent::versioned(
            EventTopic::LightClientOptimisticUpdate,
            ForkName::Gloas,
            exit.to_json(),
        );
        assert_eq!(
            event.render(),
            b"event: light_client_optimistic_update\ndata: {\"version\":\"gloas\",\"data\":{\"epoch\":\"1\",\"validator_index\":\"7\"}}\n\n".to_vec()
        );
    }
}
