//! The TLS 1.2 client state machine, entered when the server answers the hello with TLS 1.2.

use std::{fmt, hint::black_box, mem};

use super::{
    Tls12Key, Tls12Secrets, Tls12Suite,
    message::{
        Certificate12, CertificateRequest12, ClientKeyExchange, Finished12, ServerKeyExchange,
        VERIFY_DATA_LEN,
    },
    prf::Prf,
};
use crate::{
    ClientConfig, Level, NamedGroup, ProtocolError, SignatureScheme, TlsError, TlsOutput, Verifier,
    extension::ExtensionType,
    group::KeyShareSecret,
    handshake::Context,
    message::{HandshakeType, Message, ServerHello},
    x509::PublicKey,
};

/// Bytes of the master secret, per RFC 5246, section 8.1.
const MASTER_LEN: usize = 48;

/// The master secret, cleared when dropped.
struct MasterSecret([u8; MASTER_LEN]);

impl Drop for MasterSecret {
    fn drop(&mut self) {
        self.0.fill(0);
        black_box(&mut self.0);
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSecret(..)")
    }
}

/// Where the TLS 1.2 client stands.
#[derive(Debug)]
enum State<V: Verifier> {
    /// The ServerHello is in; the server's chain comes next.
    WaitCertificate,
    /// The chain checks out; its key must sign the key exchange.
    WaitServerKeyExchange(V::Peer, PublicKey),
    /// The key exchange checks out; a certificate request may precede the end of the flight.
    WaitServerHelloDone {
        /// The ECDHE shared secret, the premaster secret.
        premaster: [u8; 32],
        /// The group the server chose.
        group: NamedGroup,
        /// Whether the server asked for a client certificate.
        requested: bool,
    },
    /// This side's flight is out; the server's Finished ends the handshake.
    WaitFinished(MasterSecret),
    /// The handshake failed or finished.
    Done,
}

/// The TLS 1.2 client, from the ServerHello onward.
#[derive(Debug)]
pub(crate) struct Tls12Client<V: Verifier> {
    /// The negotiated suite.
    suite: Tls12Suite,
    /// The client random, from the ClientHello.
    client_random: [u8; 32],
    /// The server random.
    server_random: [u8; 32],
    /// Whether the server accepted the extended master secret.
    extended_master_secret: bool,
    /// The key share secrets of the ClientHello; the server picks one group.
    secrets: Vec<KeyShareSecret>,
    /// The signature schemes the client offered.
    schemes: Vec<SignatureScheme>,
    /// Where the handshake stands.
    state: State<V>,
}

impl<V: Verifier> Tls12Client<V> {
    /// Accepts a TLS 1.2 ServerHello.
    pub(crate) fn start(
        config: &ClientConfig,
        hello: &ServerHello<'_>,
        message: &Message,
        secrets: Vec<KeyShareSecret>,
        context: &mut Context<V>,
    ) -> Result<Self, TlsError<V::Error>> {
        let suite = Tls12Suite::from_code(hello.cipher_suite)
            .filter(|suite| config.tls12_suites.contains(suite))
            .ok_or(ProtocolError::UnofferedCipherSuite(hello.cipher_suite))?;
        let extensions = &hello.extensions;
        let mut allowed = vec![
            ExtensionType::RENEGOTIATION_INFO,
            ExtensionType::EXTENDED_MASTER_SECRET,
            ExtensionType::EC_POINT_FORMATS,
            ExtensionType::ALPN,
        ];
        if config.server_name.is_some() {
            allowed.push(ExtensionType::SERVER_NAME);
        }
        extensions.allow_only(&allowed)?;
        extensions.require_empty(ExtensionType::SERVER_NAME)?;
        extensions.require_empty(ExtensionType::EXTENDED_MASTER_SECRET)?;

        // RFC 5746, section 3.4: an initial handshake answers with an empty renegotiated_connection.
        if let Some(info) = extensions.get(ExtensionType::RENEGOTIATION_INFO)
            && info != [0]
        {
            return Err(ProtocolError::InvalidRenegotiationInfo.into());
        }
        // RFC 8422, section 5.2: the server's formats must include the uncompressed one.
        if let Some(formats) = extensions.get(ExtensionType::EC_POINT_FORMATS)
            && !formats.split_first().is_some_and(|(&length, list)| {
                usize::from(length) == list.len() && list.contains(&0)
            })
        {
            return Err(ProtocolError::InvalidExtension(ExtensionType::EC_POINT_FORMATS.0).into());
        }
        match extensions.alpn()?.as_deref() {
            Some([protocol]) if config.alpn.iter().any(|offered| offered == protocol) => {
                context.alpn = Some(protocol.to_vec());
            }
            Some(_) => return Err(ProtocolError::UnofferedApplicationProtocol.into()),
            None if config.require_alpn => {
                return Err(ProtocolError::NoApplicationProtocol.into());
            }
            None => {}
        }
        context.transcript.update(message.raw());
        Ok(Self {
            suite,
            client_random: context.randomness.random,
            server_random: hello.random,
            extended_master_secret: extensions
                .get(ExtensionType::EXTENDED_MASTER_SECRET)
                .is_some(),
            secrets,
            schemes: config.signature_schemes.clone(),
            state: State::WaitCertificate,
        })
    }

    /// Advances by one received message.
    ///
    /// # Returns
    ///
    /// Whether the handshake has finished.
    pub(crate) fn handle(
        &mut self,
        message: &Message,
        context: &mut Context<V>,
    ) -> Result<bool, TlsError<V::Error>> {
        let state = mem::replace(&mut self.state, State::Done);
        self.state = match (state, message.kind()) {
            (State::WaitCertificate, HandshakeType::CERTIFICATE) => {
                let chain = Certificate12::parse(message.body())?.chain;
                let (peer, key) = context.verify_chain(&chain)?;
                // The suite fixes the type of key the server authenticates with.
                let fits = match key {
                    PublicKey::P256(_) | PublicKey::P384(_) => self.suite.is_ecdsa(),
                    PublicKey::Rsa(_) => !self.suite.is_ecdsa(),
                };
                if !fits {
                    return Err(ProtocolError::KeyTypeMismatch.into());
                }
                context.transcript.update(message.raw());
                State::WaitServerKeyExchange(peer, key)
            }
            (State::WaitServerKeyExchange(peer, key), HandshakeType::SERVER_KEY_EXCHANGE) => {
                let (premaster, group) = self.server_key_exchange(message, &key)?;
                context.transcript.update(message.raw());
                context.peer = Some(peer);
                State::WaitServerHelloDone {
                    premaster,
                    group,
                    requested: false,
                }
            }
            (
                State::WaitServerHelloDone {
                    premaster,
                    group,
                    requested: false,
                },
                HandshakeType::CERTIFICATE_REQUEST,
            ) => {
                CertificateRequest12::check(message.body())?;
                context.transcript.update(message.raw());
                State::WaitServerHelloDone {
                    premaster,
                    group,
                    requested: true,
                }
            }
            (
                State::WaitServerHelloDone {
                    mut premaster,
                    group,
                    requested,
                },
                HandshakeType::SERVER_HELLO_DONE,
            ) => {
                if !message.body().is_empty() {
                    return Err(ProtocolError::TrailingBytes {
                        count: message.body().len(),
                    }
                    .into());
                }
                context.transcript.update(message.raw());
                let master = self.send_flight(&premaster, group, requested, context)?;
                premaster.fill(0);
                State::WaitFinished(master)
            }
            (State::WaitFinished(master), HandshakeType::FINISHED) => {
                let received = Finished12::parse(message.body())?;
                let expected = Self::verify_data(&master, b"server finished", context);
                // Fold every byte difference, so the time does not reveal where they differ.
                let difference = expected
                    .iter()
                    .zip(&received)
                    .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
                if black_box(difference) != 0 {
                    return Err(ProtocolError::InvalidFinished.into());
                }
                context.transcript.update(message.raw());
                return Ok(true);
            }
            (state, _) => return Err(message.unexpected(state.waiting_for()).into()),
        };
        Ok(false)
    }

    /// Checks the signed key exchange and returns the premaster secret and the server's group.
    fn server_key_exchange(
        &self,
        message: &Message,
        key: &PublicKey,
    ) -> Result<([u8; 32], NamedGroup), ProtocolError> {
        let exchange = ServerKeyExchange::parse(message.body())?;
        let secret = self
            .secrets
            .iter()
            .find(|secret| secret.group() == exchange.group)
            .ok_or(ProtocolError::UnofferedGroup(exchange.group.0))?;
        if !self.schemes.contains(&exchange.scheme) {
            return Err(ProtocolError::UnofferedSignatureScheme(exchange.scheme.0));
        }
        let signed = [
            &self.client_random[..],
            &self.server_random[..],
            exchange.params,
        ]
        .concat();
        exchange
            .scheme
            .verify(key, &signed, exchange.signature, false)
            .map_err(|_| ProtocolError::InvalidKeyExchangeSignature)?;
        Ok((secret.agree(exchange.public)?, exchange.group))
    }

    /// Sends ClientKeyExchange, ChangeCipherSpec and Finished, and installs the record keys.
    fn send_flight(
        &self,
        premaster: &[u8; 32],
        group: NamedGroup,
        requested: bool,
        context: &mut Context<V>,
    ) -> Result<MasterSecret, TlsError<V::Error>> {
        let secret = self
            .secrets
            .iter()
            .find(|secret| secret.group() == group)
            .ok_or(ProtocolError::UnofferedGroup(group.0))?;
        let mut flight = Vec::new();
        // RFC 5246, section 7.4.6: a client without a certificate sends an empty list.
        if requested {
            flight.extend(context.send(Certificate12::encode_empty()));
        }
        flight.extend(context.send(ClientKeyExchange::encode(&secret.public())));
        context.emit(Level::Initial, flight);

        // RFC 7627, section 4: the extended master secret binds the transcript so far.
        let mut master = MasterSecret([0; MASTER_LEN]);
        let prf = Prf::new(premaster);
        if self.extended_master_secret {
            prf.expand(
                b"extended master secret",
                &[&context.transcript.hash()],
                &mut master.0,
            );
        } else {
            prf.expand(
                b"master secret",
                &[&self.client_random, &self.server_random],
                &mut master.0,
            );
        }

        // RFC 5246, section 6.3: client key, server key, client IV, server IV.
        let suite = self.suite;
        let (key_len, iv_len) = (suite.key_len(), suite.iv_len());
        let mut block = [0_u8; 2 * 32 + 2 * 12];
        let block = &mut block[..2 * (key_len + iv_len)];
        Prf::new(&master.0).expand(
            b"key expansion",
            &[&self.server_random, &self.client_random],
            block,
        );
        let key = |offset: usize, iv_offset: usize| {
            let mut out = Tls12Key {
                suite,
                key: [0; 32],
                iv: [0; 12],
            };
            out.key[..key_len].copy_from_slice(&block[offset..offset + key_len]);
            out.iv[..iv_len].copy_from_slice(&block[iv_offset..iv_offset + iv_len]);
            out
        };
        let secrets = Tls12Secrets {
            local: key(0, 2 * key_len),
            remote: key(key_len, 2 * key_len + iv_len),
        };
        block.fill(0);
        context.output.push_back(TlsOutput::Tls12Keys(secrets));
        context.output.push_back(TlsOutput::ChangeCipherSpec);

        let verify_data = Self::verify_data(&master, b"client finished", context);
        let finished = context.send(Finished12::encode(&verify_data));
        context.emit(Level::Application, finished);
        context.buffer.advance(Level::Application)?;
        Ok(master)
    }

    /// The Finished verify data under a label, over the transcript so far.
    fn verify_data(
        master: &MasterSecret,
        label: &[u8],
        context: &Context<V>,
    ) -> [u8; VERIFY_DATA_LEN] {
        let mut out = [0_u8; VERIFY_DATA_LEN];
        Prf::new(&master.0).expand(label, &[&context.transcript.hash()], &mut out);
        out
    }
}

impl<V: Verifier> State<V> {
    /// What the state waits for, for error messages.
    const fn waiting_for(&self) -> &'static str {
        match self {
            Self::WaitCertificate => "waiting for the TLS 1.2 server Certificate",
            Self::WaitServerKeyExchange(..) => "waiting for ServerKeyExchange",
            Self::WaitServerHelloDone { .. } => "waiting for ServerHelloDone",
            Self::WaitFinished(_) => "waiting for the TLS 1.2 server Finished",
            Self::Done => "done",
        }
    }
}
