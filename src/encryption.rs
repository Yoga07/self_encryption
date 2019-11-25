// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

// TODO(dirvine) Look at aessafe 256X8 cbc it should be very much faster  :01/03/2015

use aes::Aes128;
use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use crate::sequential::Key;

pub type DecryptionError = ();

pub fn encrypt(data: &mut [u8], &Key(key): &Key) -> Vec<u8> {
    let arr = GenericArray::clone_from_slice(&key);
    let mut block = GenericArray::clone_from_slice(data);
    let aes = Aes128::new(&arr);
    aes.encrypt_block(&mut block);
    data.to_vec()
}

pub fn decrypt(encrypted_data: &mut [u8], &Key(key): &Key) -> Result<Vec<u8>, DecryptionError> {
    let arr = GenericArray::clone_from_slice(&key);
    let mut block = GenericArray::clone_from_slice(encrypted_data);
    let aes = Aes128::new(&arr);
    aes.decrypt_block(&mut block);
    Ok(block.to_vec())
}
