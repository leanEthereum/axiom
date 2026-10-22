//! Forwardings kept alive over PCP, RFC 6887.

use std::net::Ipv4Addr;

use tokio::time::Instant;
use tracing::{debug, warn};

use super::{
    CodecError, Forwarding, Listener, MappedEndpoint, MappingProtocol, NatError,
    control::ControlSocket,
    epoch::{EpochRule, GatewayEpoch},
    pcp::{NONCE_LEN, PcpMapRequest, PcpMapResponse},
    session::{DELETE_ATTEMPTS, REQUESTED_LIFETIME},
};

/// The forwardings one PCP server granted, under one nonce.
#[derive(Debug)]
pub(crate) struct PcpSession {
    /// The socket to the server.
    socket: ControlSocket,
    /// The nonce every request carries; the server ties the mappings to it.
    nonce: [u8; NONCE_LEN],
    /// The local ports to forward.
    listeners: Vec<(Listener, u16)>,
    /// The forwardings granted at the last pass.
    granted: Vec<Forwarding>,
    /// The external address the server assigned.
    external: Ipv4Addr,
    /// The server's epoch, for restart detection.
    epoch: GatewayEpoch,
    /// The local clock the epoch checks count from.
    started: Instant,
}

impl PcpSession {
    /// Asks the server for every forwarding.
    ///
    /// # Errors
    ///
    /// Fails when the server speaks another version, the exchange fails, or nothing is granted.
    pub(crate) async fn establish(
        socket: ControlSocket,
        listeners: Vec<(Listener, u16)>,
        nonce: [u8; NONCE_LEN],
    ) -> Result<Self, NatError> {
        let mut session = Self {
            socket,
            nonce,
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

    /// Renews every forwarding, recreating them all if the server restarted.
    ///
    /// # Errors
    ///
    /// Fails when the exchange fails or nothing is granted any more.
    pub(crate) async fn renew(&mut self) -> Result<(), NatError> {
        self.map_all().await
    }

    /// Deletes every forwarding with a zero lifetime, per RFC 6887 section 15.
    ///
    /// Deletion is advisory: a lost request leaves a mapping to expire on its own.
    pub(crate) async fn release(self) {
        for forwarding in &self.granted {
            let request = PcpMapRequest {
                client: self.socket.local_ip(),
                nonce: self.nonce,
                transport: forwarding.listener.transport(),
                internal: forwarding.internal,
                suggested_port: 0,
                suggested_ip: Ipv4Addr::UNSPECIFIED,
                lifetime: 0,
            };
            let deleted = self
                .socket
                .exchange_with(
                    &request.encode(),
                    |bytes| request.decode_response(bytes),
                    DELETE_ATTEMPTS,
                )
                .await;
            match deleted {
                Ok(_) => debug!(listener = %forwarding.listener, "PCP mapping deleted"),
                Err(error) => debug!(%error, listener = %forwarding.listener, "PCP deletion lost"),
            }
        }
    }

    /// Maps every listener once, and once more if the server restarted midway.
    async fn map_all(&mut self) -> Result<(), NatError> {
        // A restart seen at the first answer of a pass lost only the old mappings.
        // This pass recreates them anyway.
        // A restart seen later lost the ones this pass already made, so the pass runs again.
        for _ in 0..2 {
            let mut granted = Vec::new();
            let mut external = None;
            let mut restarted_midway = false;
            for (index, &(listener, internal)) in self.listeners.iter().enumerate() {
                let Some(response) = self.map(listener, internal).await? else {
                    continue;
                };
                if self
                    .epoch
                    .lost_state(EpochRule::Pcp, self.started.elapsed(), response.epoch)
                {
                    warn!(listener = %listener, "PCP server lost its mappings; mapping again");
                    restarted_midway = index > 0;
                }
                external.get_or_insert(response.external_ip);
                granted.push(Forwarding {
                    listener,
                    internal,
                    external: response.external_port,
                    lifetime: response.lifetime,
                });
                if restarted_midway {
                    break;
                }
            }
            // Invariant: a pass cut short keeps the earlier grants, which the next pass suggests.
            if restarted_midway {
                continue;
            }
            self.granted = granted;
            if let Some(external) = external {
                self.external = external;
            }
            break;
        }
        if self.granted.is_empty() {
            return Err(NatError::NothingMapped {
                protocol: MappingProtocol::Pcp,
                asked: self.listeners.len(),
            });
        }
        Ok(())
    }

    /// Maps one listener, suggesting the port and address it held before.
    ///
    /// # Returns
    ///
    /// Nothing when the server refused this one forwarding; others may still pass.
    async fn map(
        &self,
        listener: Listener,
        internal: u16,
    ) -> Result<Option<PcpMapResponse>, NatError> {
        // A renewal suggests what the server granted, so a restarted server can grant it again.
        let previous = self.granted.iter().find(|held| held.listener == listener);
        let request = PcpMapRequest {
            client: self.socket.local_ip(),
            nonce: self.nonce,
            transport: listener.transport(),
            internal,
            suggested_port: previous.map_or(internal, |held| held.external),
            suggested_ip: previous.map_or(Ipv4Addr::UNSPECIFIED, |_| self.external),
            lifetime: REQUESTED_LIFETIME,
        };
        match self
            .socket
            .exchange(&request.encode(), |bytes| request.decode_response(bytes))
            .await
        {
            Ok(response) => Ok(Some(response)),
            Err(NatError::Codec(error @ CodecError::Refused { .. })) => {
                warn!(%error, listener = %listener, port = internal, "PCP mapping refused");
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}
