#![cfg(feature = "nif")]

use crate::TransferLogic;
use arm::rustler_util::{at_struct, RustlerDecoder, RustlerEncoder};
use transfer_witness::SimpleTransferWitness;
use rustler::types::map::map_new;
use rustler::{atoms, Decoder, Encoder, Env, NifResult, Term};

atoms! {
    at_transfer_logic = "Elixir.AnomaPay.NIF.TransferLogic",
    at_witness = "witness"

}

// impl Encoder for TransferLogic {
//     fn encode<'a>(&self, env: Env<'a>) -> Term<'a> {
//         let map = map_new(env)
//             .map_put(at_struct().encode(env), at_transfer_logic().encode(env))
//             .unwrap()
//             .map_put(
//                 at_witness().encode(env),
//                 self.witness.rustler_encode(env).unwrap(),
//             )
//             .expect("failed");
//         map
//     }
// }
//
// impl<'a> Decoder<'a> for TransferLogic {
//     fn decode(term: Term<'a>) -> NifResult<Self> {
//         let witness_term = term.map_get(at_witness().encode(term.get_env()))?;
//         let witness: SimpleTransferWitness = RustlerDecoder::rustler_decode(witness_term)?;
//         Ok(TransferLogic { witness })
//     }
// }
