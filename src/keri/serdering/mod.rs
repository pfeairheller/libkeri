use crate::cesr::number::Number;
use crate::cesr::tholder::Tholder;
use crate::cesr::verfer::Verfer;
use crate::cesr::{dig_dex, Versionage};
use crate::errors::MatterError;
use crate::keri;
use crate::keri::{deversify, smell, Ilk, KERIError, Kinds, Smellage};
use keri::{Ilks, Saids};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{self, Value};
use std::collections::HashMap;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use tracing::error;
use tracing::metadata::Kind;
use crate::cesr::diger::Diger;

/// A comprehensive struct containing all possible KERI event fields
/// with Option<T> for fields that aren't required by all event types
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Sadder {
    /// Version string - required in all events
    pub v: String,

    /// Type/ilk identifier (e.g., "icp", "rot", "ixn", etc.) - required in all events
    pub t: String,

    /// Self-addressing identifier (digest) - required in all events
    pub d: String,

    /// Identifier - required in most events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i: Option<String>,

    /// Sequence number - required in most events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<String>,

    /// Previous digest - used in rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,

    /// Key threshold - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kt: Option<String>,

    /// Keys - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub k: Option<Vec<String>>,

    /// Next key threshold - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nt: Option<String>,

    /// Next keys - used in key management events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<Vec<String>>,

    /// Backer threshold - inception and some other events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bt: Option<String>,

    /// Backers - inception and some other events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub b: Option<Vec<String>>,

    /// Uuid - Properties for vcp  (registry  inception event)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,

    /// Configuration traits - inception events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<Vec<String>>,

    /// Anchors or additional data - various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a: Option<Vec<String>>,

    /// Anchors or additional data - various events
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "A")]
    pub cap_a: Option<Vec<String>>,

    /// Route - used in query/reply events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<String>,

    /// Query parameters - used in query events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<Value>,

    /// Delegator identifier - used in delegation events (DIP, DRT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub di: Option<String>,

    /// Timestamp - used in various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dt: Option<String>,

    /// Registry identifier - used in registry events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ri: Option<String>,

    /// Seals - used in various events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal: Option<Vec<Value>>,

    /// Receipt - used in receipt events (RCT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rct: Option<Value>,

    /// Witness receipts - used in witness events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wr: Option<Vec<Value>>,

    /// Witness removal - rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub br: Option<Vec<String>>,

    /// Witness add - rotation events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ba: Option<Vec<String>>,

    /// Credential issuance data - used in credential events (ISS, REV)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ii: Option<String>,

    /// Schema reference - used in schema and credential events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sr: Option<String>,

    /// Rule data - used for rule events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Value>,

    /// Edge data - used for graph/edge events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<Value>,

    /// Aggregate data - used for aggregate events
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ag: Option<Value>,

    /// Attachments for credentials or other data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at: Option<Vec<Value>>,
}

impl Sadder {
    /// Creates a new basic KeriEvent with mandatory fields
    pub fn new(version: String, ilk: String, digest: String) -> Self {
        Self {
            v: version,
            t: ilk,
            d: digest,
            ..Default::default()
        }
    }

    /// Creates a specific event type from this general structure
    pub fn ilk(&self) -> Result<Ilk, &KERIError> {
        match self.t.as_str() {
            Ilks::ICP => Ok(Ilk::Icp),
            Ilks::ROT => Ok(Ilk::Rot),
            Ilks::IXN => Ok(Ilk::Ixn),
            Ilks::DIP => Ok(Ilk::Dip),
            Ilks::DRT => Ok(Ilk::Drt),
            Ilks::RCT => Ok(Ilk::Rct),
            Ilks::QRY => Ok(Ilk::Qry),
            Ilks::RPY => Ok(Ilk::Rpy),
            Ilks::VCP => Ok(Ilk::Vcp),
            Ilks::VRT => Ok(Ilk::Vrt),
            Ilks::ISS => Ok(Ilk::Iss),
            Ilks::REV => Ok(Ilk::Rev),
            _ => Err(&KERIError::FieldError(String::from("Unknown event type"))),
        }
    }

    /// Determine if this event is a key state establishment event
    pub fn is_establishment_event(&self) -> bool {
        matches!(
            self.t.as_str(),
            Ilks::ICP | Ilks::ROT | Ilks::DIP | Ilks::DRT | Ilks::VCP | Ilks::VRT | Ilks::RIP
        )
    }

    fn get_primary_said_label(&self) -> Option<&str> {
        match &self.ilk() {
            Ok(ilk) => match ilk {
                Ilk::Icp => Some(Saids::D),
                Ilk::Rot => Some(Saids::D),
                Ilk::Ixn => Some(Saids::D),
                Ilk::Dip => Some(Saids::D),
                Ilk::Drt => Some(Saids::D),
                Ilk::Qry => Some(Saids::D),
                Ilk::Rpy => Some(Saids::D),
                Ilk::Pro => Some(Saids::D),
                Ilk::Bar => Some(Saids::D),
                Ilk::Exn => Some(Saids::D),
                Ilk::Vcp => Some(Saids::D),
                Ilk::Vrt => Some(Saids::D),
                Ilk::Iss => Some(Saids::D),
                Ilk::Rev => Some(Saids::D),
                Ilk::Bis => Some(Saids::D),
                Ilk::Brv => Some(Saids::D),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Base implementation of the Serder trait for serializable/deserializable entities
pub struct BaseSerder {
    /// Serialized message as bytes
    raw: Vec<u8>,
    /// Serializable attribute dictionary (key event dict)
    sad: Sadder,
    /// CESR code table version
    cvrsn: Versionage,
    /// Protocol identifier type (e.g., 'KERI' or 'ACDC')
    proto: String,
    /// Event version information
    vrsn: Versionage,
    /// Serialization kind (json, cbor, msgpack, binary)
    kind: Kinds,
    /// Number of bytes in serialized event
    size: usize,
    /// qb64 self-addressing identifier given by appropriate saidive field
    said: Option<String>,
    /// CESR genus code for this Serder
    genus: String,
    /// CESR genus code table version for this Serder
    gvrsn: Versionage,
}

impl BaseSerder {
    /// Returns an error if verification fails or if required fields are missing
    pub fn from_raw(raw: &[u8], smellage: Option<Smellage>) -> Result<Self, KERIError> {
        // Create a new BaseSerder instance
        // Inhale the raw data (equivalent to _inhale in Python)
        // Parse smellage or smell the raw data
        let (proto, vrsn, kind, size, _gvrsn) = match smellage {
            Some(smell) => {
                // Use provided smellage
                (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn)
            }
            None => {
                // Smell the raw data
                let smell = smell(raw)?;
                (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn)
            }
        };

        // Deserialize data based on kind
        let sad = BaseSerder::loads(raw, Some(size), Kinds::from(&kind)?)?;

        // Verify version field exists
        let mut serder = BaseSerder {
            raw: raw[..size].to_vec(),
            sad,
            cvrsn,
            proto,
            vrsn,
            kind: Kinds::from(&kind)?,
            size,
            said: None,
            genus,
            gvrsn,
        };

        // Get the primary said field label
        let label = match sad.get_primary_said_label() {
            Some(label) => label,
            None => {
                // Set said to None (null in Python)
                serder.said = None;
                return Ok(serder);
            }
        };

        // Check if the primary said field exists in the sad
        if let Some(sad) = &serder.sad {
            if let Some(said) = sad.get(label) {
                // Extract the said (not verified yet)
                serder.said = Some(said.to_string());
            } else {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));
            }
        } else {
            serder.said = None;
        }

        // Note: In Rust, we don't modify the passed-in raw buffer directly
        // The strip functionality would be implemented elsewhere if needed

        // Verify fields including the saids provided in raw
        match serder.verify() {
            Ok(_) => Ok(serder),
            Err(err) => {
                // Log the error
                error!("Invalid raw for Serder {}\n{}", serder.pretty(None), err);

                Err(MatterError::ValidationError(format!(
                    "Invalid raw for Serder = {:?}. {}",
                    serder.sad, err
                )))
            }
        }
    }

    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let smell = deversify(sad)?;
        let (proto, vrsn, kind, size, _gvrsn) =
            (smell.proto, smell.vrsn, smell.kind, smell.size, smell.gvrsn);
        // Verify version field exists

        let raw = BaseSerder::dumps(sad, &Kinds::from(kind.as_str())?)?;

        let mut serder = BaseSerder {
            raw: raw[..size].to_vec(),
            sad: sad.clone(),
            cvrsn,
            proto,
            vrsn,
            kind: Kinds::from(&kind)?,
            size,
            said: None,
            genus,
            gvrsn,
        };

        // Get the primary said field label
        let label = match sad.get_primary_said_label() {
            Some(label) => label,
            None => {
                // Set said to None (null in Python)
                serder.said = None;
                return Ok(serder);
            }
        };

        // Check if the primary said field exists in the sad
        if let Some(sad) = &serder.sad {
            if let Some(said) = sad.get(label) {
                // Extract the said (not verified yet)
                serder.said = Some(said.to_string());
            } else {
                return Err(KERIError::FieldError(format!(
                    "Missing primary said field in {:?}.",
                    sad
                )));
            }
        } else {
            serder.said = None;
        }

        // Note: In Rust, we don't modify the passed-in raw buffer directly
        // The strip functionality would be implemented elsewhere if needed

        // Verify fields including the saids provided in raw
        match serder.verify() {
            Ok(_) => Ok(serder),
            Err(err) => {
                // Log the error
                error!("Invalid raw for Serder {}\n{}", serder.pretty(None), err);

                Err(MatterError::ValidationError(format!(
                    "Invalid raw for Serder = {:?}. {}",
                    serder.sad, err
                )))
            }
        }
    }

    /// Computes the self-addressing identifier (SAID) for the given raw data and genus.
    ///
    /// # Arguments
    ///
    /// * `raw` - Byte slice of the serialized message.
    /// * `genus` - The CESR genus code associated with the event.
    ///
    /// # Returns
    ///
    /// * `Result<String, KERIError>` - The computed SAID as a base64-encoded string on success,
    ///                                   or a KERIError on failure.
    fn compute_said(raw: &[u8], genus: &str) -> Result<String, KERIError> {
        // Use the appropriate hashing algorithm based on the genus code.
        let hash = match genus {
            "BLAKE3" => blake3::hash(raw).to_hex().to_string(),
            "SHA256" => {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(raw);
                BASE64_STANDARD.encode(hasher.finalize())
            }
            "SHA3_256" => {
                use sha3::{Digest, Sha3_256};
                let mut hasher = Sha3_256::new();
                hasher.update(raw);
                BASE64_STANDARD.encode(hasher.finalize())
            }
            _ => {
                return Err(KERIError::FieldError(format!(
                    "Unsupported genus code for SAID computation: {}",
                    genus
                )));
            }
        };

        Ok(hash)
    }

    // Helper method to get the primary said field label
    fn get_primary_said_label(&self) -> Option<&str> {
        self.sad.get_primary_said_label()
    }

    /// Deserializes raw bytes into a data structure based on the specified kind
    ///
    /// # Arguments
    ///
    /// * `raw` - Raw bytes to deserialize
    /// * `size` - Number of bytes to consume for deserialization (if None, uses all bytes)
    /// * `kind` - Serialization format (JSON, MGPK, CBOR)
    ///
    /// # Returns
    ///
    /// A Result containing either the deserialized data or a KERIError
    ///
    /// # Notes
    ///
    /// JSON deserialization uses UTF-8 string conversion, while CBOR and MGPK operate directly on bytes
    pub fn loads(raw: &[u8], size: Option<usize>, kind: Kinds) -> Result<Sadder, KERIError> {
        // Determine how many bytes to use
        let limit = size.unwrap_or(raw.len());
        let data = &raw[..std::cmp::min(limit, raw.len())];

        match kind {
            Kinds::Json => {
                // Convert bytes to UTF-8 string for JSON
                match std::str::from_utf8(data) {
                    Ok(text) => {
                        let sadder: Sadder = serde_json::from_str(text).unwrap();
                        Ok(sadder)
                    }
                    Err(e) => Err(KERIError::JsonError(format!(
                        "Invalid UTF-8 sequence: {}",
                        e
                    ))),
                }
            }

            Kinds::Mgpk => {
                // For msgpack, direct deserialization from bytes
                // In a real implementation, you would use the rmp_serde crate
                // This is a placeholder that simulates the error handling pattern
                Err(KERIError::MgpkError(
                    "MGPK deserialization not implemented".to_string(),
                ))

                // A real implementation might look like:
                // rmp_serde::from_slice(data)
                //     .map_err(|e| KERIError::MgpkError(
                //         format!("{}: {:?}", e, data)
                //     ))
            }

            Kinds::Cbor => {
                // For CBOR, direct deserialization from bytes
                // In a real implementation, you would use the ciborium crate
                // This is a placeholder that simulates the error handling pattern
                Err(KERIError::CborError(
                    "CBOR deserialization not implemented".to_string(),
                ))

                // A real implementation might look like:
                // let mut deserializer = ciborium::de::Deserializer::from_reader(data);
                // let value = serde::de::Deserialize::deserialize(&mut deserializer)
                //     .map_err(|e| KERIError::CborError(
                //         format!("{}: {:?}", e, data)
                //     ));
                // value
            }
        }
    }

    ///
    /// # Parameters:
    /// * `sad`: Optional data to serialize. If None, uses default empty data
    /// * `kind`: Serialization format (Json, Cbor, MsgPack)
    /// * `proto`: Optional protocol type
    /// * `vrsn`: Optional protocol version
    ///
    /// # Returns:
    /// Serialized bytes of the data
    ///
    /// # Errors:
    /// Returns a KERIError if serialization fails
    pub fn dumps<T: Serialize>(sad: &Sadder, kind: &Kinds) -> Result<Vec<u8>, KERIError> {
        let data = match sad {
            Some(d) => d,
            None => {
                return Err(KERIError::FieldError(
                    "No data provided for serialization".to_string(),
                ))
            }
        };

        match kind {
            Kinds::Json => match serde_json::to_string(data) {
                Ok(json_str) => Ok(json_str.into_bytes()),
                Err(e) => Err(KERIError::DeserializeError(e.to_string())),
            },
            Kinds::Mgpk => {
                #[cfg(feature = "msgpack")]
                {
                    match rmp_serde::to_vec(data) {
                        Ok(bytes) => Ok(bytes),
                        Err(e) => Err(KERIError::DeserializeError(DeserializeError::MgpkError(
                            e.to_string(),
                        ))),
                    }
                }

                #[cfg(not(feature = "msgpack"))]
                {
                    Err(KERIError::DeserializeError(
                        "MsgPack serialization not enabled".to_string(),
                    ))
                }
            }
            Kinds::Cbor => {
                #[cfg(feature = "cbor")]
                {
                    match serde_cbor::to_vec(data) {
                        Ok(bytes) => Ok(bytes),
                        Err(e) => Err(KERIError::DeserializeError(DeserializeError::CborError(
                            e.to_string(),
                        ))),
                    }
                }

                #[cfg(not(feature = "cbor"))]
                {
                    Err(KERIError::DeserializeError(
                        "CBOR serialization not enabled".to_string(),
                    ))
                }
            }
        }
    }

    pub fn verify(&self) -> Result<(), KERIError> {
        // Call the potentially overridden _verify method
        self._verify()
    }

}

/// Trait representing a serializable/deserializable entity with SAID (Self-Addressing IDentifier)
pub trait Serder {
    /// Returns a pretty-printed JSON representation of the serialized data
    ///
    /// # Parameters
    /// * `size` - Optional size limit for the output. None means no limit.
    ///   This protects against syslog errors when exceeding UDP MTU.
    ///   IPv4 MTU is 576, IPv6 MTU is 1280, and most broadband routers have 1454 MTU.
    fn pretty(&self, size: Option<usize>) -> String;

    /// Returns the raw bytes representation
    fn raw(&self) -> &[u8];

    /// Returns a copy of the serializable attribute dictionary (saidified data)
    fn sad(&self) -> HashMap<String, Value>;

    /// Returns the CESR genus code for this Serder
    fn genus(&self) -> &str;

    /// Returns the CESR genus code table version for this Serder
    fn gvrsn(&self) -> &Versionage;

    /// Returns the serialization kind (value of Serials/Serialage)
    fn kind(&self) -> &str;

    /// Returns the protocol identifier type (e.g., 'KERI' or 'ACDC')
    fn proto(&self) -> &str;

    /// Alias for proto() - returns the protocol identifier type
    fn protocol(&self) -> &str {
        self.proto()
    }

    /// Returns the protocol version for this Serder
    fn vrsn(&self) -> &Versionage;

    /// Alias for vrsn() - returns the protocol version
    fn version(&self) -> &Versionage {
        self.vrsn()
    }

    /// Returns the number of bytes in the raw representation
    fn size(&self) -> usize;

    /// Returns the qb64 SAID (Self-Addressing IDentifier)
    fn said(&self) -> Option<&str>;

    /// Returns the qb64b (bytes) representation of the SAID
    fn saidb(&self) -> Option<Vec<u8>> {
        self.said().map(|s| s.as_bytes().to_vec())
    }

    /// Returns the packet type given by sad['t'] if any
    fn ilk(&self) -> Option<&str>;
}

impl Serder for BaseSerder {
    fn pretty(&self, size: Option<usize>) -> String {
        let json_str = serde_json::to_string_pretty(&self.sad)
            .unwrap_or_else(|_| "Error serializing to JSON".to_string());

        if let Some(limit) = size {
            if json_str.len() > limit {
                return json_str[..limit].to_string();
            }
        }

        json_str
    }

    fn raw(&self) -> &[u8] {
        &self.raw
    }

    fn sad(&self) -> Sadder {
        self.sad.clone() // Return a copy
    }

    fn genus(&self) -> &str {
        &self.genus
    }

    fn gvrsn(&self) -> &Versionage {
        &self.gvrsn
    }

    fn kind(&self) -> &str {
        self.kind.to_string().as_str()
    }

    fn proto(&self) -> &str {
        &self.proto
    }

    fn vrsn(&self) -> &Versionage {
        &self.vrsn
    }

    fn size(&self) -> usize {
        self.size
    }

    fn said(&self) -> Option<&str> {
        self.said.as_deref()
    }

    fn ilk(&self) -> Option<&str> {
        Some(self.sad.t.as_str())
    }
}

// Define a trait for verification behavior
pub trait Verifiable {
    // Default implementation that can be overridden
    fn _verify(&self) -> Result<(), KERIError> {
        // Default behavior
        Ok(())
    }
}

// Implement the trait for BaseSerder
impl Verifiable for BaseSerder {
    // You can override the default implementation if needed
    fn _verify(&self) -> Result<(), KERIError> {
        // Verify that the required SAID field is present. This is a critical field for integrity checks.
        if let Some(said) = &self.said {
            // Compute the expected SAID based on the self-addressing hash of the serialized message.
            let computed_said = Self::compute_said(&self.raw, &self.genus)?;

            // Compare the computed SAID with the provided SAID.
            if *said != computed_said {
                return Err(KERIError::ValidationError(format!(
                    "SAID mismatch: expected {}, found {}",
                    computed_said, said
                )));
            }
        } else {
            // If the SAID is None, verification fails since it's a required field.
            return Err(KERIError::FieldError("Missing SAID field.".to_string()));
        }

        // Additional checks can be added here for other required fields or properties.

        Ok(())
    }
}


/// KERI-specific implementation of the Serder
pub struct SerderKERI {
    base: BaseSerder,
}

impl SerderKERI {
    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from raw bytes.
    pub fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
    }

    /// Creates a new `SerderKERI` by constructing its `BaseSerder` from a sad.
    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let base = BaseSerder::from_sad(sad)?;
        Ok(Self { base })
    }

    /// Returns true if Serder represents an establishment event
    pub fn estive(&self) -> bool {
        if let Some(t) = self.base.sad.t.as_ref() {
            matches!(t.as_str(), "icp" | "rot" | "dip" | "drt")
        } else {
            false
        }
    }

    /// Returns key event dict property getter. Alias for .sad
    pub fn ked(&self) -> Sadder {
        self.base.sad.clone()
    }

    /// Returns qb64 of .sad["i"] identifier prefix
    pub fn pre(&self) -> Option<String> {
        self.base.sad.i.clone()
    }

    /// Returns qb64b of .pre identifier prefix as bytes
    pub fn preb(&self) -> Option<Vec<u8>> {
        self.pre().map(|pre| pre.into_bytes())
    }

    /// Number instance of sequence number
    pub fn sner(&self) -> Option<Number> {
        let num = Number::from_numh(self.base.sad.s.as_ref().unwrap_or(&"0".to_string()));
        match num {
            Ok(num) => Some(num),
            Err(e) => {
                error!("Error parsing sequence number: {}", e);
                None
            }
        }
    }

    /// Sequence number as integer
    pub fn sn(&self) -> Option<u64> {
        match self.sner() {
            Some(num) => Some(num.num() as u64),
            None => None,
        }
    }

    /// Sequence number as hex string
    pub fn snh(&self) -> Option<String> {
        self.sner().map(|sner| sner.numh())
    }

    /// Seals from .sad["a"]
    pub fn seals(&self) -> Option<Vec<String>> {
        self.base.sad.a.clone()
    }

    /// Traits list (config traits) from .sad["c"]
    pub fn traits(&self) -> Option<Vec<String>> {
        self.base.sad.c.clone()
    }

    /// Tholder instance as converted from .sad['kt']
    pub fn tholder(&self) -> Option<Tholder> {
        let thold = Tholder::from_str(self.base.sad.kt.as_ref().unwrap_or(&"0".to_string()));
        match thold {
            Ok(thold) => Some(thold),
            Err(e) => {
                error!("Error parsing threshold: {}", e);
                None
            }
        }
    }

    /// List of qb64 keys from .sad['k']
    pub fn keys(&self) -> Option<Vec<String>> {
        self.base.sad.k.clone()
    }

    /// List of Verfer instances as converted from .sad['k']
    pub fn verfers(&self) -> Option<Vec<Verfer>> {
        self.keys().and_then(|keys| {
            let mut verfers = Vec::new();
            for key in keys.iter() {
                match Verfer::from_qb64(key) {
                    Ok(verfer) => verfers.push(verfer),
                    Err(_) => return None,
                }
            }
            Some(verfers)
        })
    }

    /// Tholder instance as converted from .sad['nt']
    pub fn ntholder(&self) -> Option<Tholder> {
        let thold = Tholder::from_str(self.base.sad.nt.as_ref().unwrap_or(&"0".to_string()));
        match thold {
            Ok(thold) => Some(thold),
            Err(e) => {
                error!("Error parsing next threshold: {}", e);
                None
            }
        }
    }

    /// Next key digests from .sad['n']
    pub fn ndigs(&self) -> Option<Vec<String>> {
        // Check version condition like in Python
        if self.base.vrsn.major < 2 && self.base.vrsn.minor < 1 && self.base.sad.t == "vcp" {
            return None;
        }

        self.base.sad.n.clone()
    }

    /// List of Diger instances as converted from .sad['n']
    pub fn ndigers(&self) -> Option<Vec<Diger>> {
        self.ndigs().and_then(|digs| {
            let mut digers = Vec::new();
            for dig in digs.iter() {
                match Diger::from_qb64(dig) {
                    Ok(diger) => digers.push(diger),
                    Err(_) => return None,
                }
            }
            Some(digers)
        })
    }

    /// Number of backer TOAD threshold
    pub fn bner(&self) -> Option<Number> {
        let num = Number::from_numh(self.base.sad.bt.as_ref().unwrap_or(&"0".to_string()));
        match num {
            Ok(num) => Some(num),
            Err(e) => {
                error!("Error parsing sequence number: {}", e);
                None
            }
        }
    }

    /// Backer TOAD number as integer
    pub fn bn(&self) -> Option<u64> {
        match self.sner() {
            Some(num) => Some(num.num() as u64),
            None => None,
        }
    }

    /// Backers list from .sad['b']
    pub fn backs(&self) -> Option<Vec<String>> {
        self.base.sad.b.clone()
    }

    /// List of Verfer instances as converted from .sad['b']
    pub fn berfers(&self) -> Option<Vec<Verfer>> {
        self.backs().and_then(|keys| {
            let mut verfers = Vec::new();
            for key in keys.iter() {
                match Verfer::from_qb64(key) {
                    Ok(verfer) => verfers.push(verfer),
                    Err(_) => return None,
                }
            }
            Some(verfers)
        })
    }

    /// Prior event SAID from .sad['p']
    pub fn prior(&self) -> Option<String> {
        self.base.sad.p.clone()
    }

    /// Prior event SAID as bytes
    pub fn priorb(&self) -> Option<Vec<u8>> {
        self.prior().map(|prior| prior.into_bytes())
    }

    /// List of backers to be cut (removed) from .sad['br']
    pub fn cuts(&self) -> Option<Vec<String>> {
        self.base.sad.br.clone()
    }

    /// List of backers to be added from .sad['ba']
    pub fn adds(&self) -> Option<Vec<String>> {
        self.base.sad.ba.clone()
    }

    /// Delegator ID prefix from .sad["di"]
    pub fn delpre(&self) -> Option<String> {
        self.base.sad.di.clone()
    }

    /// Delegator ID prefix as bytes
    pub fn delpreb(&self) -> Option<Vec<u8>> {
        self.delpre().map(|delpre| delpre.into_bytes())
    }

    /// Date-time-stamp from .sad["dt"]
    pub fn stamp(&self) -> Option<String> {
        self.base.sad.dt.clone()
    }

    /// UUID (salty nonce) from .sad["u"]
    pub fn uuid(&self) -> Option<String> {
        self.base.sad.u.clone()
    }

    /// Alias for .uuid property with version check
    pub fn nonce(&self) -> Option<String> {
        if self.base.vrsn.major < 2 && self.base.vrsn.minor < 1 && self.base.sad.t == "vcp" {
            // In earlier versions, nonce was stored in 'n' field
            self.base.sad.n.as_ref().map(|n| n[0].clone())
        } else {
            self.uuid()
        }
    }

    /// Get the ilk of the event
    pub fn ilk(&self) -> Option<Ilk> {
        Ilk::from_str(&self.base.sad.t)
    }
}

// Override the verification for the derived struct
impl Verifiable for SerderKERI {
    fn _verify(&self) -> Result<(), KERIError> {
        // First call the base implementation
        self.base._verify()?;

        // Then add SerderKERI-specific verification
        // Additional verification logic here

        Ok(())
    }
}

/// Helper function to parse version string into Versionage
fn parse_version(version_str: &str) -> Result<Versionage, String> {
    let parts: Vec<&str> = version_str.split('.').collect();

    if parts.len() != 2 {
        return Err(format!("Invalid version format: {}", version_str));
    }

    let major = match parts[0].parse::<u32>() {
        Ok(num) => num,
        Err(_) => return Err(format!("Invalid major version: {}", parts[0])),
    };

    let minor = match parts[1].parse::<u32>() {
        Ok(num) => num,
        Err(_) => return Err(format!("Invalid minor version: {}", parts[1])),
    };

    Ok(Versionage { major, minor })
}

/// SerderACDC struct that extends BaseSerder
pub struct SerderACDC {
    /// Base Serder fields and behavior
    pub base: BaseSerder,
}

impl SerderACDC {
    /// Creates a new `SerderACDC` by constructing its `BaseSerder` from raw bytes.
    pub fn from_raw(raw: &[u8], smell: Option<Smellage>) -> Result<Self, KERIError> {
        let base = BaseSerder::from_raw(raw, smell)?;
        Ok(Self { base })
    }

    /// Creates a new `SerderACDC` by constructing its `BaseSerder` from a sad.
    pub fn from_sad(sad: &Sadder) -> Result<Self, KERIError> {
        let base = BaseSerder::from_sad(sad)?;
        Ok(Self { base })
    }


    /// uuid property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["u"] salty nonce
    pub fn uuid(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.u.as_ref() {
            if let Value::String(s) = value {
                return Some(s);
            }
        }
        None
    }

    /// uuidb property getter (uuid bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .sad["u"] salty nonce as bytes
    pub fn uuidb(&self) -> Option<Vec<u8>> {
        self.uuid().map(|s| s.as_bytes().to_vec())
    }

    /// issuer property getter (issuer AID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["i"] issuer AID
    pub fn issuer(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.i.as_ref() {
            if let Value::String(s) = value {
                return Some(s);
            }
        }
        None
    }

    /// issuerb property getter (issuer AID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuer AID as bytes
    pub fn issuerb(&self) -> Option<Vec<u8>> {
        self.issuer().map(|s| s.as_bytes().to_vec())
    }

    /// regi property getter (registry identifier SAID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["ri"] registry SAID
    pub fn regi(&self) -> Option<&str> {
        if let Some(value) = self.base.sad.ri.as_ref() {
            if let Value::String(s) = value {
                return Some(s);
            }
        }
        None
    }

    /// regib property getter (registry identifier SAID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuer AID as bytes
    pub fn regib(&self) -> Option<Vec<u8>> {
        // Note: There's a bug in the Python implementation that uses self.issuer here
        // Fixing it to use self.regi instead
        self.regi().map(|s| s.as_bytes().to_vec())
    }

    /// schema block or SAID property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&serde_json::Value>: from ._sad["s"]
    pub fn schema(&self) -> Option<&String> {
        self.base.sad.s.as_ref()
    }

    /// attrib block or SAID property getter (attribute)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&String>: from ._sad["a"]
    pub fn attrib(&self) -> Option<&Vec<String>> {
        self.base.sad.a.as_ref()
    }

    /// issuee property getter (issuee AID)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<String>: qb64 of .sad["a"]["i"] issuee AID
    pub fn issuee(&self) -> Option<&str> {
        if let Some(attrib) = self.attrib() {
            if let Value::Object(obj) = attrib {
                if let Some(Value::String(s)) = obj.get("i") {
                    return Some(s);
                }
            }
        }
        None
    }

    /// issueeb property getter (issuee AID bytes)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<Vec<u8>>: qb64b of .issuee AID as bytes
    pub fn issueeb(&self) -> Option<Vec<u8>> {
        self.issuee().map(|s| s.as_bytes().to_vec())
    }

    /// attagg block property getter (attribute aggregate)
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&serde_json::Value>: from ._sad["A"]
    pub fn attagg(&self) -> Option<&Vec<String>> {
        self.base.sad.cap_a.as_ref()
    }

    /// edge block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&serde_json::Value>: from ._sad["e"]
    pub fn edge(&self) -> Option<&Value> {
        self.base.sad.e.as_ref()
    }

    /// rule block property getter
    /// Optional fields return None when not present
    ///
    /// Returns:
    ///    Option<&serde_json::Value>: from ._sad["r"]
    pub fn rule(&self) -> Option<&String> {
        self.base.sad.r.as_ref()
    }
}

// Implement the Serder trait for SerderACDC (assuming we have a trait as discussed)
impl Verifiable for SerderACDC {
    fn _verify(&self) -> Result<(), KERIError> {
        // First verify base fields
        self.base._verify()?;

        // Add ACDC-specific verification
        // This could include validating the schema, issuer, etc.

        Ok(())
    }
}

impl SerderACDC {
    /// Public verification method that delegates to the trait method
    pub fn verify(&self) -> Result<(), KERIError> {
        self._verify()
    }
}

#[cfg(test)]
mod tests {}
