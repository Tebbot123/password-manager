use argon2::Argon2;

pub fn derive_key(salt: &[u8], password: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let argon2 = Argon2::default();
    
    match argon2.hash_password_into(password, salt, &mut key) {
        Ok(_) => key,
        Err(e) => panic!("{}", e)
    }
}

#[cfg(test)]
mod tests {
    use crate::encryption::key_gen::derive_key;

    #[test]
    fn generate_derive_key() {
        let password = "Hello World!";
        let salt = "aWv2QVjmOIb+VYMlm6Z7rA";
        let key = derive_key(salt.as_bytes(), &password.as_bytes());

        assert_eq!(hex::encode(key), "0c96360edf27e04a87119ae3089a4d45d00987caa4b6d9df3a9e3df6bc495df1".to_string())
    }
}