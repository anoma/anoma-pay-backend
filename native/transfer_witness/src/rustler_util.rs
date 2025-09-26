#![cfg(feature = "nif")]

use crate::{AuthorizationInfo, EncryptionInfo, ForwarderInfo, PermitInfo, SimpleTransferWitness};
use arm::authorization::{AuthorizationSignature, AuthorizationVerifyingKey};
use arm::encryption::{AffinePoint, SecretKey};
use arm::evm::CallType;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::rustler_util::{at_struct, RustlerDecoder, RustlerEncoder};
use rustler::types::map::map_new;
use rustler::{atoms, Atom, Decoder, Encoder, Env, Error, NifResult, Term};

atoms! {
    at_simple_transfer_witness = "AnomaPay.SimpleTransferWitness",
    at_authorization_info = "AnomaPay.AuthorizationInfo",
    at_encryption_info_struct = "AnomaPay.EncryptionInfoStruct",
    at_forwarder_info_struct = "AnomaPay.ForwarderInfoStruct",
    at_call_type = "call_type",
    at_forwarder_addr = "forwarder_addr",
    at_token_addr = "token_addr",
    at_user_addr = "user_addr",
    at_permit_info = "permit_info",
    at_is_consumed = "is_consumed",
    at_existence_path = "existence_path",
    at_nf_key = "nf_key",
    at_auth_info = "auth_info",
    at_encryption_info = "encryption_info",
    at_forwarder_info = "forwarder_info",
    at_auth_pk = "auth_pk",
    at_auth_sig = "auth_sig",
    at_encryption_pk = "encryption_pk",
    at_sender_sk = "sender_sk",
    at_encryption_nonce = "encryption_nonce",
    at_discovery_cipher = "discovery_cipher",
    at_permit_nonce = "permit_nonce",
    at_permit_deadline = "permit_deadline",
    at_permit_sig = "permit_sig",
}

macro_rules! atom {
    ($env:expr, $s:expr) => {
        Atom::from_str($env, $s).expect(concat!("failed to encode ", $s))
    };
}

macro_rules! fetch {
    ($term:expr, $key:expr) => {{
        let key_atom = atom!($term.get_env(), $key);
        let key_term = $term.map_get(key_atom)?;
        RustlerDecoder::rustler_decode(key_term)?
    }};
}

macro_rules! maybe_fetch {
    ($term:expr, $key:expr) => {{
        let key_atom = atom!($term.get_env(), $key);
        let key_term = $term.map_get(key_atom)?;
        if key_term.is_atom() {
            None
        } else {
            Some(RustlerDecoder::rustler_decode(key_term)?)
        }
    }};
}


macro_rules! build_map {
    ($env:expr; $(($key:literal, $value:expr $(=> $encoder:ident)?)),* $(,)?) => {{
        let mut map = map_new($env);
        $(
            map = map.map_put(
                Atom::from_str($env, $key).expect(concat!("failed to encode ", $key)).encode($env),
                build_map!(@encode $value, $env $(, $encoder)?)
            )?;
        )*
        map
    }};

    // Default to .encode()
    (@encode $value:expr, $env:expr) => {
        $value.encode($env)
    };

    // Use specified encoder
    (@encode $value:expr, $env:expr, rustler_encode) => {
        $value.rustler_encode($env)?
    };
}
//--------------------------------------------------------------------------------------------------
// AuthorizationInfo

impl RustlerEncoder for AuthorizationInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let map = build_map!(env;
        ("__struct__", atom!(env, "AnomaPay.AuthorizationInfo")),
        ("auth_pk", self.auth_pk),
        ("auth_sig", self.auth_sig));

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for AuthorizationInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let auth_pk: AuthorizationVerifyingKey = fetch!(term, "auth_pk");
        let auth_sig: AuthorizationSignature = fetch!(term, "auth_sig");
        Ok({ AuthorizationInfo { auth_pk, auth_sig } })
    }
}

impl Encoder for AuthorizationInfo {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode AuthorizationInfo")
    }
}

impl<'a> Decoder<'a> for AuthorizationInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        AuthorizationInfo::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// EncryptionInfo

impl RustlerEncoder for EncryptionInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let map = build_map!(env;
        ("__struct__", atom!(env, "AnomaPay.EncryptionInfo")),
        ("encryption_pk", self.encryption_pk => rustler_encode),
        ("sender_sk", self.sender_sk),
        ("encryption_nonce", self.encryption_nonce),
        ("discovery_cipher", self.discovery_cipher));

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for EncryptionInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let encryption_pk : AffinePoint = fetch!(term, "encryption_pk");
        let sender_sk : SecretKey = fetch!(term, "sender_sk");
        let encryption_nonce : Vec<u8> = fetch!(term, "encryption_nonce");
        let discovery_cipher : Vec<u32> = fetch!(term, "discovery_cipher");

        Ok({
            EncryptionInfo {
                encryption_pk,
                sender_sk,
                encryption_nonce,
                discovery_cipher,
            }
        })
    }
}

impl Encoder for EncryptionInfo {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode EncryptionInfo")
    }
}

impl<'a> Decoder<'a> for EncryptionInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        EncryptionInfo::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// PermitInfo

impl RustlerEncoder for PermitInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        Ok(map_new(env)
            .map_put(
                at_struct().encode(env),
                at_encryption_info_struct().encode(env),
            )?
            .map_put(
                at_permit_nonce().encode(env),
                self.permit_nonce.rustler_encode(env).unwrap(),
            )?
            .map_put(
                at_permit_deadline().encode(env),
                self.permit_deadline.encode(env),
            )?
            .map_put(at_permit_sig().encode(env), self.permit_sig.encode(env))?)
    }
}

impl<'a> RustlerDecoder<'a> for PermitInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let permit_nonce: Vec<u8> = RustlerDecoder::rustler_decode(
            term.map_get(at_permit_nonce().encode(term.get_env()))?,
        )?;
        let permit_deadline: Vec<u8> = RustlerDecoder::rustler_decode(
            term.map_get(at_permit_deadline().encode(term.get_env()))?,
        )?;
        let permit_sig: Vec<u8> =
            RustlerDecoder::rustler_decode(term.map_get(at_permit_sig().encode(term.get_env()))?)?;

        Ok(PermitInfo {
            permit_deadline,
            permit_nonce,
            permit_sig,
        })
    }
}

impl Encoder for PermitInfo {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode PermitInfo")
    }
}

impl<'a> Decoder<'a> for PermitInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        PermitInfo::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// ForwarderInfo

impl RustlerEncoder for ForwarderInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        Ok(map_new(env)
            .map_put(
                at_struct().encode(env),
                at_forwarder_info_struct().encode(env),
            )?
            .map_put(at_call_type().encode(env), self.call_type.encode(env))?)
    }
}

impl<'a> RustlerDecoder<'a> for ForwarderInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let call_type: CallType =
            RustlerDecoder::rustler_decode(term.map_get(at_call_type().encode(term.get_env()))?)?;
        let forwarder_addr: Vec<u8> = RustlerDecoder::rustler_decode(
            term.map_get(at_forwarder_addr().encode(term.get_env()))?,
        )?;
        let token_addr: Vec<u8> =
            RustlerDecoder::rustler_decode(term.map_get(at_token_addr().encode(term.get_env()))?)?;
        let user_addr: Vec<u8> =
            RustlerDecoder::rustler_decode(term.map_get(at_user_addr().encode(term.get_env()))?)?;

        // decode Option<PermitInfo>
        let mut permit_info: Option<PermitInfo> = None;
        let permit_info_term = term.map_get(at_permit_info().encode(term.get_env()))?;
        if !permit_info_term.is_atom() {
            permit_info = Some(RustlerDecoder::rustler_decode(permit_info_term)?);
        }

        Ok(ForwarderInfo {
            call_type,
            forwarder_addr,
            token_addr,
            user_addr,
            permit_info,
        })
    }
}

impl Encoder for ForwarderInfo {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode ForwarderInfo")
    }
}

impl<'a> Decoder<'a> for ForwarderInfo {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        ForwarderInfo::rustler_decode(term)
    }
}

//--------------------------------------------------------------------------------------------------
// SimpleTransferWitness

impl RustlerEncoder for SimpleTransferWitness {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let map = build_map!(env;
            ("__struct__", atom!(env, "AnomaPay.SimpleTransferWitness")),
            ("is_consumed", self.is_consumed),
            ("existence_path", self.existence_path),
            ("nf_key", self.nf_key),
            ("auth_info", self.auth_info),
            ("encryption_info", self.encryption_info),
        );

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for SimpleTransferWitness {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let resource: Resource = fetch!(term, "resource");
        let is_consumed: bool = fetch!(term, "is_consumed");
        let existence_path: MerklePath = fetch!(term, "existence_path");
        let nf_key: Option<NullifierKey> = maybe_fetch!(term, "nf_key");
        let auth_info: Option<AuthorizationInfo> = maybe_fetch!(term, "auth_info");
        let encryption_info: Option<EncryptionInfo> = maybe_fetch!(term, "encryption_info");
        let forwarder_info: Option<ForwarderInfo> = maybe_fetch!(term, "forwarder_info");
        Ok(SimpleTransferWitness {
            resource,
            is_consumed,
            existence_path,
            nf_key,
            auth_info,
            encryption_info,
            forwarder_info,
        })
    }
}

impl Encoder for SimpleTransferWitness {
    fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
        let encoded = self.rustler_encode(env);
        encoded.expect("failed to encode SimpleTransferWitness")
    }
}

impl<'a> Decoder<'a> for SimpleTransferWitness {
    fn decode(term: Term<'a>) -> NifResult<Self> {
        SimpleTransferWitness::rustler_decode(term)
    }
}
