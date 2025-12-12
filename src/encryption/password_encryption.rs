use std::str::from_utf8;

use aes_gcm::{Aes256Gcm, Error, Key, KeyInit, Nonce, aead::Aead};
use rand::{RngCore, rngs::OsRng};

pub struct DecodedBlob {
    pub nonce: Vec<u8>,
    pub cypher_text: Vec<u8>
}

pub fn encrypt_text(text: &str, key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes[..]);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let cypher_text = match cipher.encrypt(nonce, text.as_bytes()) {
        Ok(s) => s,
        Err(e) => {return Err(e);}
    };


    let parsed_blob = match parse_blob(&cypher_text, &nonce_bytes) {
        Ok(v) => v,
        Err(e) => {return Err(e);}
    };

    Ok(parsed_blob)
}

pub fn decrypt_text(blob: &[u8], key: &[u8]) -> Result<String, aes_gcm::Error> {
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    
    let decoded_blob = decode_blob(blob)?;

    let nonce = Nonce::from_slice(&decoded_blob.nonce);


    let text = match cipher.decrypt(nonce, &*decoded_blob.cypher_text) {
        Ok(v) => v,
        Err(e) => {return Err(e);}
    };

    let format_text = from_utf8(&text).unwrap();
    Ok(format_text.to_string())
}

pub fn parse_blob(cyphertext: &[u8], blob: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
    let mut result = Vec::with_capacity(blob.len() + cyphertext.len());
    result.extend_from_slice(blob);
    result.extend_from_slice(cyphertext);
    Ok(result)
}

pub fn decode_blob(blob: &[u8]) -> Result<DecodedBlob, aes_gcm::Error> {
    if blob.len() < 12 {
        return Err(aes_gcm::Error);
    }
    let (nonce_bytes, cyphertext) = blob.split_at(12);
    Ok(DecodedBlob {
        nonce: nonce_bytes.to_owned(),
        cypher_text: cyphertext.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use crate::encryption::password_encryption::{decode_blob, decrypt_text, encrypt_text, parse_blob};

    #[test]
    fn parse_valid_blob() {
         // 0202020202020202020202020202020248656c6c6f20776f726c6421
         let blob = parse_blob("Hello world!".as_bytes(), &[2u8; 12]).unwrap();
         assert_eq!(hex::encode(blob), "02020202020202020202020248656c6c6f20776f726c6421")
    }

    #[test]
    fn test_decode_blob() {    
        let decoded_blob = decode_blob(&hex::decode("02020202020202020202020248656c6c6f20776f726c6421").unwrap()).unwrap();
        assert_eq!(decoded_blob.nonce, [2u8; 12]);
        assert_eq!(decoded_blob.cypher_text, "Hello world!".as_bytes());
    }

    #[test]
    fn encrypt_text_test() {
        let key = "0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1";
        let text = "Hello world";
        encrypt_text(text, &hex::decode(key).unwrap()).unwrap();
    }

    #[test]
    fn decrypt_text_test() {
        let cypher_text = hex::decode("fb02f7f6726214b38ea2b336e45afa0b1b65170fce23e07a5e66efdc9417884e64935df014c6c4").unwrap();
        let key = "0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1";
        assert_eq!(decrypt_text(&cypher_text, &hex::decode(key).unwrap()).unwrap(), "Hello world");
    }
}