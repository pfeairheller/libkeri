use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};
use crate::keri::{Ilk, KERIError};
use crate::keri::serdering::{Serder, SerderACDC, SerderKERI, Serdery};
use crate::cesr::cigar::Cigar;
use crate::cesr::dater::Dater;
use crate::cesr::prefixer::Prefixer;
use crate::cesr::seqner::Seqner;
use crate::cesr::saider::Saider;
use crate::cesr::indexing::siger::Siger;
use crate::cesr::{sniff, VRSN_1_0};
use crate::cesr::COLDS;
use crate::cesr::diger::Diger;
use crate::cesr::pather::Pather;
use crate::cesr::texter::Texter;

/// Trans Indexed Sig Groups
#[derive(Debug, Clone)]
pub struct Tsgs {
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct Trqs {
    prefixer: Prefixer,
    seqner: Seqner,
    diger: Diger,
    siger: Siger,
}

#[derive(Debug, Clone)]
pub struct Trrs {
    prefixer: Prefixer,
    seqner: Seqner,
}

#[derive(Debug, Clone)]
pub struct Ssgs {
    prefixer: Prefixer,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct Frcs {
    seqner: Seqner,
    dater: Dater,
}

#[derive(Debug, Clone)]
pub struct Ssts {
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
}

#[derive(Debug, Clone)]
pub struct Sscs {
    seqner: Seqner,
    saider: Saider,
}

/// Trans Indexed Sig Groups
#[derive(Debug, Clone)]
pub struct SadTsgs {
    path: Pather,
    prefixer: Prefixer,
    seqner: Seqner,
    saider: Saider,
    sigers: Vec<Siger>,
}

#[derive(Debug, Clone)]
pub struct SadCigars {
    path: Pather,
    cigars: Vec<Cigar>,
}


/// Represents all possible parsed messages from a KERI stream that can be processed
/// by Kevery, Tevery, Exchanger, Revery, or Verifier
pub enum Message {
    /// Identifier key event messages
    KeyEvent {
        serder: Box<dyn Serder>,
        sigers: Option<Vec<Siger>>,
        wigers: Option<Vec<Siger>>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        local: Option<bool>,
    },

    /// Non-transferable receipt messages
    Receipt {
        serder: Box<dyn Serder>,
        cigars: Vec<Cigar>,
        local: Option<bool>,
    },

    /// Witness receipt messages
    WitnessReceipt {
        serder: Box<dyn Serder>,
        wigers: Vec<Siger>,
        local: Option<bool>,
    },

    /// Transferable receipt messages
    ReceiptTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
        local: Option<bool>,
    },

    /// Query messages for Kevery or Tevery
    Query {
        serder: Box<dyn Serder>,
        source: Option<Prefixer>,
        sigers: Option<Vec<Siger>>,
        cigar: Option<Vec<Cigar>>,
    },

    /// Reply messages for Revery with non-transferable signatures
    ReplyNonTrans {
        serder: Box<dyn Serder>,
        cigars: Vec<Cigar>,
    },

    /// Reply messages for Revery with transferable signatures
    ReplyTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
    },

    /// Event messages for Exchanger with non-transferable signatures
    ExchangeEventNonTrans {
        serder: Box<dyn Serder>,
        cigars: Vec<Cigar>,
        pathed: Option<Vec<Vec<u8>>>,
        essrs: Option<Vec<Texter>>,
    },

    /// Event messages for Exchanger with transferable signatures
    ExchangeEventTrans {
        serder: Box<dyn Serder>,
        tsgs: Vec<Tsgs>,
        pathed: Option<Vec<Vec<u8>>>,
        essrs: Option<Vec<Texter>>,
    },

    /// TEL events for Tevery
    TELEvent {
        serder: Box<dyn Serder>,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
        wigers: Option<Vec<Siger>>,
    },

    /// Credential messages for Verifier
    Credential {
        creder: Box<dyn Serder>,
        prefixer: Option<Prefixer>,
        seqner: Option<Seqner>,
        saider: Option<Saider>,
    },
}

// Implementation with helper methods
impl Message {
    /// Creates a new Event message
    pub fn new_event(
        serder: Box<dyn Serder>,
        sigers: Option<Vec<Siger>>,
        wigers: Option<Vec<Siger>>,
        delseqner: Option<Seqner>,
        delsaider: Option<Saider>,
        firner: Option<Seqner>,
        dater: Option<Dater>,
        local: Option<bool>,
    ) -> Self {
        Message::KeyEvent {
            serder,
            sigers,
            wigers,
            delseqner,
            delsaider,
            firner,
            dater,
            local,
        }
    }

    /// Creates a new Receipt message
    pub fn new_receipt(serder: Box<dyn Serder>, cigars: Vec<Cigar>, local: Option<bool>) -> Self {
        Message::Receipt {
            serder,
            cigars,
            local,
        }
    }

    // Add similar factory methods for other variants...

    /// Returns the serder from any message type
    pub fn serder(&self) -> &Box<dyn Serder> {
        match self {
            Message::KeyEvent { serder, .. } => serder,
            Message::Receipt { serder, .. } => serder,
            Message::WitnessReceipt { serder, .. } => serder,
            Message::ReceiptTrans { serder, .. } => serder,
            Message::Query { serder, .. } => serder,
            Message::ReplyNonTrans { serder, .. } => serder,
            Message::ReplyTrans { serder, .. } => serder,
            Message::ExchangeEventNonTrans { serder, .. } => serder,
            Message::ExchangeEventTrans { serder, .. } => serder,
            Message::TELEvent { serder, .. } => serder,
            Message::Credential { creder, .. } => creder,
        }
    }

    /// Determines if the message is local
    pub fn is_local(&self) -> bool {
        match self {
            Message::KeyEvent { local, .. } => local.unwrap_or(false),
            Message::Receipt { local, .. } => local.unwrap_or(false),
            Message::WitnessReceipt { local, .. } => local.unwrap_or(false),
            Message::ReceiptTrans { local, .. } => local.unwrap_or(false),
            _ => false,
        }
    }
}
// Traits for message handlers
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    async fn handle(&self, msg: Message) -> Result<(), KERIError>;
}

pub struct Parser<R> {
    reader: R,
    buffer: Vec<u8>,
    framed: bool,
    pipeline: bool,
    handlers: Handlers,
    serdery: Serdery
}
pub struct Handlers {
    pub kevery: Arc<dyn MessageHandler>,
    pub tevery: Arc<dyn MessageHandler>,
    pub exchanger: Arc<dyn MessageHandler>,
    pub revery: Arc<dyn MessageHandler>,
    pub verifier: Arc<dyn MessageHandler>,
    pub local: bool,
}

impl<R: AsyncRead + Unpin + Send> Parser<R> {
    pub fn new(reader: R, framed: bool, pipeline: bool, handlers: Handlers) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            framed,
            pipeline,
            handlers,
            serdery: Serdery::new()
        }
    }

    pub async fn parse_stream(&mut self) -> Result<(), KERIError> {
        loop {
            // Read data asynchronously into buffer
            let mut chunk = vec![0u8; 4096];
            let n = self.reader.read(&mut chunk).await?;
            if n == 0 {
                break; // EOF
            }
            self.buffer.extend_from_slice(&chunk[..n]);

            // Process buffer into messages
            while let Some((msg, consumed)) = self.try_parse_message()? {
                self.dispatch_message(msg).await?;
                self.buffer.drain(..consumed);
            }
        }
        Ok(())
    }

    fn try_parse_message(&self) -> Result<Option<(Message, usize)>, KERIError> {
        let serder = self.serdery.reap(self.buffer.as_slice(), "-AAAA", &VRSN_1_0, None, None)?;
        let serder_size = serder.size();
        match sniff(self.buffer.as_slice()) {
            Ok(cold) => {
                if cold == COLDS.msg {
                    return Ok(None);
                }


                let mut attachment_size = 0;

                // TODO: Parser attachments

                attachment_size += 0;
                Ok(Some((Message::new_event(serder, None, None, None, None, None, None, None), serder_size + attachment_size)))
            }
            Err(_) => {
                Err(KERIError::Shortage("Short on the sniff".to_string()))
            }
        }
    }

    async fn dispatch_message(&self, msg: Message) -> Result<(), KERIError> {
        // Match message type to handler
        match msg {
                Message::KeyEvent { serder: _, sigers: _, wigers: _, delseqner: _, delsaider: _, firner: _, dater: _, local: _ } => {
                    self.handlers.kevery.handle(msg).await?
                }
                Message::Receipt { serder: _, cigars: _, local: _ } => {
                    self.handlers.kevery.handle(msg).await?
                }
                Message::WitnessReceipt { serder: _, wigers: _, local: _ } => {
                    self.handlers.kevery.handle(msg).await?
                }
                Message::ReceiptTrans { serder: _, tsgs: _, local: _ }  => {
                    self.handlers.kevery.handle(msg).await?
                }
                Message::Query { serder: _, source: _, sigers: _, cigar: _ } => {
                    let serder = msg.serder();
                    let ilk = serder.ilk();
                    match ilk {
                        Some(ilk) => {
                            match ilk {
                                "logs" | "ksn" | "mbx" => {
                                    self.handlers.kevery.handle(msg).await?
                                }
                                "tels" | "tsn" => {
                                    self.handlers.tevery.handle(msg).await?
                                }
                                &_ => {}
                            }
                        }
                        None => {}
                    }
                }
                Message::ReplyNonTrans { serder: _, cigars: _ }  => {
                    self.handlers.revery.handle(msg).await?
                }
                Message::ReplyTrans { serder: _, tsgs: _ } => {
                    self.handlers.revery.handle(msg).await?
                }
                Message::ExchangeEventNonTrans { serder: _, cigars: _, pathed: _, essrs: _ } => {
                    self.handlers.exchanger.handle(msg).await?
                }
                Message::ExchangeEventTrans { serder: _, tsgs: _, pathed: _, essrs: _ } => {
                    self.handlers.exchanger.handle(msg).await?
                }
                Message::TELEvent { serder: _, seqner: _, saider: _, wigers: _ } => {
                    self.handlers.tevery.handle(msg).await?
                }
                Message::Credential { creder: _, prefixer: _, seqner: _, saider: _ } => {
                    self.handlers.verifier.handle(msg).await?
                }
            }
        Ok(())
    }

    // This would typically go inside the impl block for Parser
    fn process_message(&self, serder: Box<dyn Serder>,
                       sigers: Vec<Siger>,
                       wigers: Vec<Siger>,
                       cigars: Vec<Cigar>,
                       tsgs: Vec<Tsgs>,
                       ssgs: Vec<Ssgs>,
                       sscs: Vec<Sscs>,
                       frcs: Vec<Frcs>,
                       ssts: Vec<Ssts>,
                       pathed: Vec<Vec<u8>>,
                       sadtsgs: Vec<SadTsgs>,
                       sadcigars: Vec<SadCigars>,
                       essrs: Vec<Texter>,
                       prefixer: Option<Prefixer>,
                       local: bool) -> Result<Message, KERIError> {

        // Check if serder is SerderKERI
        if let Some(keri_serder) = serder.as_any().downcast_ref::<SerderKERI>() {
            let ilk = keri_serder.ilk();

            // Check for event messages
            if ilk == Some(Ilk::Icp) || ilk == Some(Ilk::Rot) || ilk == Some(Ilk::Ixn) ||
                ilk == Some(Ilk::Dip) || ilk == Some(Ilk::Drt) {

                // Extract firner and dater from the last element of frcs
                let (firner, dater) = frcs.last().map(|frcs| (Some(frcs.seqner.clone()), Some(frcs.dater.clone()))).unwrap_or((None, None));

                // Extract delseqner and delsaider from the last element of sscs
                let (delseqner, delsaider) = sscs.last().map(|sscs| (Some(sscs.seqner.clone()), Some(sscs.saider.clone()))).unwrap_or((None, None));

                // Validate signatures
                if sigers.is_empty() {
                    let d = keri_serder.sad().d;
                    let msg = format!("Missing attached signature(s) for evt = {}", d.as_str());
                    tracing::info!("{}", msg);
                    tracing::debug!("Event Body = \n{}\n", keri_serder.pretty(None));
                    return Err(KERIError::ValidationError(msg));
                }

                // Create KeyEvent message
                let message = Message::KeyEvent {
                    serder,
                    sigers: Some(sigers),
                    wigers: if wigers.is_empty() { None } else { Some(wigers) },
                    delseqner,
                    delsaider,
                    firner,
                    dater,
                    local: Some(local),
                };

                return Ok(message);
            }
            // Receipt message
            else if ilk == Some(Ilk::Rct) {
                if cigars.is_empty() && wigers.is_empty() && tsgs.is_empty() {
                    let msg = format!("Missing attached signatures on receipt msg sn={} SAID={}",
                                      keri_serder.sn().unwrap(), keri_serder.said().unwrap());
                    tracing::info!("{}", msg);
                    tracing::debug!("Receipt body=\n{}\n", keri_serder.pretty(None));
                    return Err(KERIError::ValidationError(msg));
                }

                if !cigars.is_empty() {
                    return Ok(Message::Receipt {
                        serder,
                        cigars,
                        local: Some(local),
                    });
                }

                if !wigers.is_empty() {
                    return Ok(Message::WitnessReceipt {
                        serder,
                        wigers,
                        local: Some(local),
                    });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ReceiptTrans {
                        serder,
                        tsgs,
                        local: Some(local),
                    });
                }
            }
            // Reply message
            else if ilk == Some(Ilk::Rpy) {
                if cigars.is_empty() && tsgs.is_empty() {
                    let msg = format!("Missing attached endorser signature(s) to reply msg = {}",
                                      keri_serder.pretty(None));
                    return Err(KERIError::ValidationError(msg));
                }

                if !cigars.is_empty() {
                    return Ok(Message::ReplyNonTrans {
                        serder,
                        cigars,
                    });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ReplyTrans {
                        serder,
                        tsgs,
                    });
                }
            }
            // Query message
            else if ilk == Some(Ilk::Qry) {
                // Check for source and signatures
                return if !sscs.is_empty() {
                    let ssgs = ssgs.last().unwrap();

                    Ok(Message::Query {
                        serder,
                        source: Some(ssgs.prefixer.clone()),
                        sigers: Some(ssgs.sigers.clone()),
                        cigar: None,
                    })
                } else if !cigars.is_empty() {
                    Ok(Message::Query {
                        serder,
                        source: None,
                        sigers: None,
                        cigar: Some(cigars),
                    })
                } else {
                    let msg = format!("Missing attached requester signature(s) to key log query msg = {}",
                                      keri_serder.pretty(None));
                    Err(KERIError::ValidationError(msg))
                }
            }
            // Exchange message
            else if ilk == Some(Ilk::Exn) {
                if !cigars.is_empty() {
                    return Ok(Message::ExchangeEventNonTrans {
                        serder,
                        cigars,
                        pathed: if pathed.is_empty() { None } else { Some(pathed) },
                        essrs: if essrs.is_empty() { None } else { Some(essrs) }
                    });
                }

                if !tsgs.is_empty() {
                    return Ok(Message::ExchangeEventTrans {
                        serder,
                        tsgs,
                        pathed: if pathed.is_empty() { None } else { Some(pathed) },
                        essrs: if essrs.is_empty() { None } else { Some(essrs) }
                    });
                }

                let msg = format!("Missing attached signatures for exchange message = {}",
                                  keri_serder.pretty(None));
                return Err(KERIError::ValidationError(msg));
            }
            // TEL message
            else if ilk == Some(Ilk::Vcp) || ilk == Some(Ilk::Vrt) || ilk == Some(Ilk::Iss) ||
                ilk == Some(Ilk::Rev) || ilk == Some(Ilk::Bis) || ilk == Some(Ilk::Brv) {

                // Extract seqner and saider from sscs
                let (seqner, saider) = sscs.last().map(|sscs| (Some(sscs.seqner.clone()), Some(sscs.saider.clone()))).unwrap_or((None, None));

                return Ok(Message::TELEvent {
                    serder,
                    seqner,
                    saider,
                    wigers: if wigers.is_empty() { None } else { Some(wigers) },
                });
            }
            else {
                let msg = format!("Unexpected message ilk = {} for evt = {}",
                                  ilk.unwrap(), keri_serder.pretty(None));
                return Err(KERIError::ValidationError(msg));
            }
        }
        // Check if serder is SerderACDC
        else if let Some(acdc_serder) = serder.as_any().downcast_ref::<SerderACDC>() {
            let ilk = acdc_serder.ilk();

            return if ilk.is_none() { // default for ACDC
                // Extract prefixer, seqner, and saider from ssts
                let (prefixer, seqner, saider) = ssts.last()
                    .map(|ssts| (Some(ssts.prefixer.clone()), Some(ssts.seqner.clone()), Some(ssts.saider.clone())))
                    .unwrap_or((None, None, None));

                Ok(Message::Credential {
                    creder: serder,
                    prefixer,
                    seqner,
                    saider,
                })
            } else {
                let msg = format!("Unexpected message ilk = {:?} for evt = {}",
                                  ilk, acdc_serder.pretty(None));
                Err(KERIError::ValidationError(msg))
            }
        }
        else {
            let msg = format!("Unexpected protocol type = {} for event message = {}",
                              serder.proto(), serder.pretty(None));
            return Err(KERIError::ValidationError(msg));
        }

        // If we get here, something went wrong in the logic above
        Err(KERIError::ValidationError("Failed to process message".to_string()))
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    struct MockHandler {}

    #[async_trait::async_trait]
    impl MessageHandler for MockHandler {
        async fn handle(&self, _msg: Message) -> Result<(), KERIError> {
            Ok(())
        }}

    #[tokio::test]
    async fn test_parser_valid_message() {
        // Provide CESR-encoded message bytes matching KERIpy tests
        let input = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EIcca2-uqsicYK7-q5gxlZXuzOkqrNSL3JIaLflSOOgF","i":"DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx","s":"0","kt":"1","k":["DNG2arBDtHK_JyHRAq-emRdC6UM-yIpCAeJIWDiXp4Hx"],"nt":"1","n":["EFXIx7URwmw7AVQTBcMxPXfOOJ2YYA1SJAam69DXV8D2"],"bt":"0","b":[],"c":[],"a":[]}-AABAAApXLez5eVIs6YyR XOMDMBy4cTm2GvsilrZlcMmtBbO5twLst_jjFoEyfKTWKntEtv9JPBv1DLkqg-Im DmGPM8E"#.as_bytes();
        let reader = tokio::io::BufReader::new(input);
        let handlers = Handlers {
            kevery: Arc::new(MockHandler {}),
            tevery: Arc::new(MockHandler {}),
            exchanger: Arc::new(MockHandler {}),
            revery: Arc::new(MockHandler {}),
            verifier: Arc::new(MockHandler {}),
            local: false,
        };

        let mut parser = Parser::new(reader, true, false, handlers);
        assert!(parser.parse_stream().await.is_ok());
    }
}