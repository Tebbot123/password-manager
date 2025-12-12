use rand::{RngCore, rngs::{self}};
use serde::{Deserialize, Serialize};

use crate::encryption::{key_gen::derive_key, password_encryption::{decrypt_text, encrypt_text}};


#[derive(Serialize, Deserialize, Debug)]
pub struct Password {
    pub website: String,
    pub username: String,
    salt: String,
    password: Option<String>,
    #[serde(skip)]
    encryption_key: Option<[u8; 32]>
}

impl Password {
    pub fn new(website: String, username: String, salt: Option<String>, password: Option<String>) -> Self {
        let salt: String = match salt {
            Some(v) => v,
            None => {
                let mut random_salt = [0u8; 16];
                let mut rng = rngs::OsRng;
                rng.fill_bytes(&mut random_salt);
                hex::encode(random_salt)
            }
        };
        Self { website, username, salt, password, encryption_key: None }
    }

    pub fn derive_key(&mut self, master_key: &[u8]) {
        // add our salt to the master_key
        let mut master_key = master_key.to_vec();
        let salt = hex::decode(&self.salt).unwrap();
        master_key.extend_from_slice(&salt);
        self.encryption_key = Some(derive_key(&salt, &master_key));
    }

    pub fn set_password(&mut self, password: &str) -> Result<bool, &str> {
        if let Some(encryption_key) = self.encryption_key {
            // TODO implement AES encryption / decryption passing test for now
            self.password = Some(hex::encode(encrypt_text(password, &encryption_key).unwrap()));
            Ok(true)
        } else {
            Err("NO_DERIVE_KEY")
        }
    }

    pub fn decode_password(&self) -> Result<String, &str> {
        if let Some(encryption_key) = self.encryption_key {
            Ok(decrypt_text(&hex::decode(self.password.as_ref().unwrap()).unwrap(), &encryption_key).unwrap())
        } else {
            Err("NO_DERIVE_KEY")
        }
    }

}

#[cfg(test)]
mod tests {
    use crate::passwords::password::Password;

    #[test]
    fn instance_password() {
        let _test_password = Password::new("test.com".to_string(), "test".to_string(), None, None);

    }

    #[test]
    fn set_derive_key() {
        let mut test_password = Password::new("test.com".to_string(), "test".to_string(), None, None);
        test_password.derive_key("0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1".as_bytes());
    }

    #[test]
    fn set_password() {
        let mut test_password = Password::new("test.com".to_string(), "test".to_string(), None, None);
        test_password.derive_key("0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1".as_bytes());
        test_password.set_password("Hello world").unwrap();
    }

    #[test]
    fn decode_password() {
        let mut test_password = Password::new("test.com".to_string(), "test".to_string(), None, None);
        test_password.derive_key("0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1".as_bytes());
        test_password.set_password("Hello world").unwrap();

        assert_eq!(test_password.decode_password().unwrap(), "Hello world".to_string());
    }

    #[test]
    fn decode_password_2() {
        let mut test_password = Password::new("test.com".to_string(), "test".to_string(), None, None);
        test_password.derive_key("0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1".as_bytes());
        test_password.set_password("Hello world").unwrap();

        assert_eq!(test_password.decode_password().unwrap(), "Hello world".to_string());
    }
}

