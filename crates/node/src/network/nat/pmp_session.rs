//! Forwardings kept alive over NAT-PMP, RFC 6886.

use std::net::Ipv4Addr;

use tokio::time::Instant;
use tracing::{debug, warn};

use super::{
    CodecError, Forwarding, Listener, MappedEndpoint, MappingProtocol, NatError,
    control::ControlSocket,
    epoch::GatewayEpoch,
    pmp::{PmpRequest, PmpResponse},
    session::{DELETE_ATTEMPTS, REQUESTED_LIFETIME},
};

/// The forwardings one NAT-PMP gateway granted.
#[derive(Debug)]
pub(crate) struct PmpSession {
    /// The socket to the gateway.
    socket: ControlSocket,
    /// The local ports to forward.
    listeners: Vec<(Listener, u16)>,
    /// The forwardings granted at the last pass.
    granted: Vec<Forwarding>,
    /// The gateway's external address.
    external: Ipv4Addr,
    /// The gateway's epoch, for restart detection.
    epoch: GatewayEpoch,
    /// The local clock the epoch checks count from.
    started: Instant,
}

impl PmpSession {
    /// Asks the gateway for its address and every forwarding.
    ///
    /// # Errors
    ///
    /// Fails when the exchange fails or nothing is granted.
    pub(crate) async fn establish(
        socket: ControlSocket,
        listeners: Vec<(Listener, u16)>,
    ) -> Result<Self, NatError> {
        let mut session = Self {
            socket,
            listeners,
            granted: Vec::new(),
            external: Ipv4Addr::UNSPECIFIED,
            epoch: GatewayEpoch::default(),
            started: Instant::now(),
        };
        session.map_all().await?;
        Ok(session)
    }

    /// The external address and the ports granted.
    pub(crate) fn endpoint(&self) -> MappedEndpoint {
        MappedEndpoint::new(self.external, &self.granted)
    }

    /// The forwardings granted.
    pub(crate) fn granted(&self) -> &[Forwarding] {
        &self.granted
    }

    /// Renews every forwarding, recreating them all if the gateway restarted.
    ///
    /// # Errors
    ///
    /// Fails when the exchange fails or nothing is granted any more.
    pub(crate) async fn renew(&mut self) -> Result<(), NatError> {
        self.map_all().await
    }

    /// Deletes every forwarding, per RFC 6886 section 3.4.
    ///
    /// Deletion is advisory: a lost request leaves a mapping to expire on its own.
    pub(crate) async fn release(self) {
        for forwarding in &self.granted {
            let request = PmpRequest::delete(forwarding.listener.transport(), forwarding.internal);
            let deleted = self
                .socket
                .exchange_with(
                    &request.encode(),
                    |bytes| request.decode_response(bytes),
                    DELETE_ATTEMPTS,
                )
                .await;
            match deleted {
                Ok(_) => debug!(listener = %forwarding.listener, "NAT-PMP mapping deleted"),
                Err(error) => {
                    debug!(%error, listener = %forwarding.listener, "NAT-PMP deletion lost");
                }
            }
        }
    }

    /// Reads the address, then maps every listener, once more if the gateway restarted midway.
    async fn map_all(&mut self) -> Result<(), NatError> {
        for _ in 0..2 {
            // The address request opens each pass, so a restart before it costs nothing extra.
            let request = PmpRequest::ExternalAddress;
            let answer = self
                .socket
                .exchange(&request.encode(), |bytes| request.decode_response(bytes))
                .await?;
            if let PmpResponse::ExternalAddress { address, .. } = answer {
                self.external = address;
            }
            if self.lost_state(answer) {
                warn!("NAT-PMP gateway lost its mappings; mapping again");
            }
            let mut granted = Vec::new();
            let mut restarted_midway = false;
            for (listener, internal) in self.listeners.clone() {
                let Some(answer) = self.map(listener, internal).await? else {
                    continue;
                };
                if self.lost_state(answer) {
                    warn!(listener = %listener, "NAT-PMP gateway lost its mappings; mapping again");
                    restarted_midway = true;
                    break;
                }
                if let PmpResponse::Map {
                    external, lifetime, ..
                } = answer
                {
                    granted.push(Forwarding {
                        listener,
                        internal,
                        external,
                        lifetime,
                    });
                }
            }
            // Invariant: a pass cut short keeps the earlier grants, which the next pass suggests.
            if restarted_midway {
                continue;
            }
            self.granted = granted;
            break;
        }
        if self.granted.is_empty() {
            return Err(NatError::NothingMapped {
                protocol: MappingProtocol::NatPmp,
                asked: self.listeners.len(),
            });
        }
        Ok(())
    }

    /// Whether an answer's epoch shows the gateway lost its state since the last answer.
    fn lost_state(&mut self, answer: PmpResponse) -> bool {
        self.epoch
            .lost_state(self.started.elapsed(), answer.epoch())
    }

    /// Maps one listener, suggesting the port it held before.
    ///
    /// # Returns
    ///
    /// Nothing when the gateway refused this one forwarding; others may still pass.
    async fn map(
        &self,
        listener: Listener,
        internal: u16,
    ) -> Result<Option<PmpResponse>, NatError> {
        // A renewal names the port granted, so a restarted gateway can grant it again.
        let suggested = self
            .granted
            .iter()
            .find(|held| held.listener == listener)
            .map_or(internal, |held| held.external);
        let request = PmpRequest::Map {
            transport: listener.transport(),
            internal,
            suggested,
            lifetime: REQUESTED_LIFETIME,
        };
        match self
            .socket
            .exchange(&request.encode(), |bytes| request.decode_response(bytes))
            .await
        {
            Ok(answer) => Ok(Some(answer)),
            Err(NatError::Codec(error @ CodecError::Refused { .. })) => {
                warn!(%error, listener = %listener, port = internal, "NAT-PMP mapping refused");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
