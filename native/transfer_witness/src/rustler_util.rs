#![cfg(feature = "nif")]

use crate::{AuthorizationInfo, EncryptionInfo, ForwarderInfo, PermitInfo, SimpleTransferWitness};
use arm::authorization::{AuthorizationSignature, AuthorizationVerifyingKey};
use arm::encryption::{AffinePoint, SecretKey};
use arm::evm::CallType;
use arm::merkle_path::MerklePath;
use arm::nullifier_key::NullifierKey;
use arm::resource::Resource;
use arm::rustler_util::{RustlerDecoder, RustlerEncoder};
use rustler::types::map::map_new;
use rustler::{Atom, Decoder, Encoder, Env, Error, NifResult, Term};

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

macro_rules! encoder {
    ($type:ty) => {
        impl Encoder for $type {
            fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
                let encoded = self.rustler_encode(env);
                encoded.expect(concat!("failed to encode ", stringify!($type)))
            }
        }
    };
}

macro_rules! decoder {
    ($type:ty) => {
        impl<'a> Decoder<'a> for $type {
            fn decode(term: Term<'a>) -> NifResult<Self> {
                <$type>::rustler_decode(term)
            }
        }
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
        Ok(AuthorizationInfo { auth_pk, auth_sig })
    }
}

encoder!(AuthorizationInfo);
decoder!(AuthorizationInfo);

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
        let encryption_pk: AffinePoint = fetch!(term, "encryption_pk");
        let sender_sk: SecretKey = fetch!(term, "sender_sk");
        let encryption_nonce: Vec<u8> = fetch!(term, "encryption_nonce");
        let discovery_cipher: Vec<u32> = fetch!(term, "discovery_cipher");

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

encoder!(EncryptionInfo);
decoder!(EncryptionInfo);

//--------------------------------------------------------------------------------------------------
// PermitInfo

impl RustlerEncoder for PermitInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let map = build_map!(env;
        ("__struct__", atom!(env, "AnomaPay.PermitInfo")),
        ("permit_nonce", self.permit_nonce),
        ("permit_deadline", self.permit_deadline),
        ("permit_sig", self.permit_sig));
        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for PermitInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let permit_nonce: Vec<u8> = fetch!(term, "permit_nonce");
        let permit_deadline: Vec<u8> = fetch!(term, "permit_deadline");
        let permit_sig: Vec<u8> = fetch!(term, "permit_sig");

        Ok(PermitInfo {
            permit_deadline,
            permit_nonce,
            permit_sig,
        })
    }
}

encoder!(PermitInfo);
decoder!(PermitInfo);

//--------------------------------------------------------------------------------------------------
// ForwarderInfo

impl RustlerEncoder for ForwarderInfo {
    fn rustler_encode<'a>(&self, env: Env<'a>) -> Result<Term<'a>, Error> {
        let map = build_map!(env;
        ("__struct__", atom!(env, "AnomaPay.ForwarderInfo")),
        ("call_type", self.call_type));

        Ok(map)
    }
}

impl<'a> RustlerDecoder<'a> for ForwarderInfo {
    fn rustler_decode(term: Term<'a>) -> NifResult<Self> {
        let call_type: CallType = fetch!(term, "call_type");
        let forwarder_addr = fetch!(term, "forwarder_addr");
        let token_addr = fetch!(term, "token_addr");
        let user_addr = fetch!(term, "user_addr");
        let permit_info = maybe_fetch!(term, "permit_info");

        Ok(ForwarderInfo {
            call_type,
            forwarder_addr,
            token_addr,
            user_addr,
            permit_info,
        })
    }
}

encoder!(ForwarderInfo);
decoder!(ForwarderInfo);

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

encoder!(SimpleTransferWitness);
decoder!(SimpleTransferWitness);
