use argon2::{
    Argon2, PasswordHash, PasswordVerifier, password_hash::{PasswordHasher, SaltString}
};
use password_hash;
use rand::rngs::OsRng;


pub fn hash_password(password: &[u8]) -> Result<String, password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    match argon2.hash_password(password, &salt) {
        Ok(pass) => Ok(pass.to_string()),
        Err(error) => Err(error)
    }
}

pub fn verify_password(password: &[u8], hash: &str) -> Result<bool, password_hash::Error> {
    let password_hash = PasswordHash::new(hash).expect("Failed to parse the password hash");
    let aragon2 = Argon2::default();
    match aragon2.verify_password(password, &password_hash) {
        Ok(_) => Ok(true),
        Err(e) => match e {
            password_hash::Error::Password => Ok(false),
            _ => Err(e)
        },
    }
}

#[cfg(test)]
mod tests {

    use crate::encryption::hasher::{hash_password, verify_password};
    #[test]
    fn generate_hash() {
        let test_password = "Hello world!";
        hash_password(&test_password.as_bytes()).unwrap();
    }
    #[test]
    fn verify_hash() {
        let test_password = "Hello world!";
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$mEQKM/v78HE1r9I+39ciVA$KXk+8z2p6LGV9AgvGKd7DNfEm5cLdy0OBtcBxMwIE9Q";
        match verify_password(&test_password.as_bytes(), &hash) {
            Ok(_) => {},
            Err(e) => {
                match e {
                    password_hash::Error::Password => panic!("Password incorrect"),
                    _ => panic!("You fucked up dummy"),
                }
            }
        }
    }
    #[test]
    fn verify_incorrect_hash() {
        let test_password = "Hello world";
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$mEQKM/v78HE1r9I+39ciVA$KXk+8z2p6LGV9AgvGKd7DNfEm5cLdy0OBtcBxMwIE9Q";
        assert_eq!(verify_password(&test_password.as_bytes(), hash).unwrap(), false);
    }

    #[test]
    fn verify_uniqueness() {
        let test_password = "Hello world!";
        let hash1 = hash_password(&test_password.as_bytes()).unwrap();
        let hash2 = hash_password(&test_password.as_bytes()).unwrap();
        if hash1 == hash2 {
            panic!("Hashes are the same!")
        }
    }
}