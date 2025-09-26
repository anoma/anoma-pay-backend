use arm::authorization::{AuthorizationSignature, AuthorizationVerifyingKey};
use arm::encryption::AffinePoint;
use arm::evm::CallType;
use arm::nullifier_key::NullifierKey;
use rustler::nif;
use transfer_witness::{AuthorizationInfo, EncryptionInfo, ForwarderInfo, PermitInfo, SimpleTransferWitness};

// #[nif]
// pub fn verifying_key_nif() -> Vec<u8> {
//     TransferLogic::verifying_key_as_bytes()
// }

// #[nif]
// pub fn prove_transfer_logic(transfer_logic: TransferLogic) -> LogicVerifier {
//     transfer_logic.prove()
// }

#[nif]
pub fn test() -> Vec<SimpleTransferWitness> {
    vec![
        // SimpleTransferWitness {
        //     resource: Default::default(),
        //     is_consumed: false,
        //     existence_path: Default::default(),
        //     nf_key: None,
        //     auth_info: Some(AuthorizationInfo {
        //         auth_pk: AuthorizationVerifyingKey::default(),
        //         auth_sig: AuthorizationSignature::default(),
        //     }),
        //     encryption_info: None,
        //     forwarder_info: None,
        // },
        SimpleTransferWitness {
            resource: Default::default(),
            is_consumed: false,
            existence_path: Default::default(),
            nf_key: Some(NullifierKey::default()),
            auth_info: Some(AuthorizationInfo {
                auth_pk: AuthorizationVerifyingKey::default(),
                auth_sig: AuthorizationSignature::default(),
            }),
            encryption_info: Some(EncryptionInfo {
                encryption_pk: AffinePoint::default(),
                sender_sk: Default::default(),
                encryption_nonce: vec![],
                discovery_cipher: vec![],
            }),
            forwarder_info: Some(ForwarderInfo {
                call_type: CallType::Wrap,
                forwarder_addr: vec![],
                token_addr: vec![],
                user_addr: vec![],
                permit_info: Some(PermitInfo {
                    permit_nonce: vec![],
                    permit_deadline: vec![],
                    permit_sig: vec![],
                }),
            }),
        },
    ]
}
rustler::init!("Elixir.AnomaPay.NIF");
