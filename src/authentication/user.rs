use std::{collections::HashMap, fs, io, path::Path};

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use crate::{encryption::{hasher::{hash_password, verify_password}, key_gen::derive_key}, passwords::password::Password};

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    password_hash: Option<String>,
    derived_salt: Option<String>,
    #[serde(skip)]
    pub derived_key: Option<[u8; 32]>,
    passwords: HashMap<String, Password>
}

impl User {
    pub fn new(password_hash: Option<String>, derived_salt: Option<String>) -> Self {
        Self {
            password_hash,
            derived_salt,
            derived_key: None,
            passwords: HashMap::new()
        }
    }

    pub fn verify_hash(&mut self, password: &str) {
        if let Ok(result) = verify_password(password.as_bytes(), self.password_hash.as_ref().unwrap()) {
            if !result {
                panic!("Incorrect password")
            }
            // Generate a derived key
            let key = derive_key(&hex::decode(self.derived_salt.as_ref().unwrap()).unwrap(), password.as_bytes());
            self.derived_key = Some(key);
        }
    }

    pub fn set_password(&mut self, password: &str) {
        // Hash and store the password
        self.password_hash = Some(hash_password(password.as_bytes()).unwrap());
        // Generate a salt
        let mut salt: [u8; 16] = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        self.derived_salt = Some(hex::encode(salt));
        // Generate a derive key
        let key = derive_key(&salt, password.as_bytes());
        self.derived_key = Some(key);
    }

    pub fn add_password(&mut self, website: String, password: String, username: String) {
        let mut password_obj = Password::new(website.to_string(), username, None, None);
        password_obj.derive_key(&self.derived_key.unwrap()); // Panics if somehow the password has not been entrerd, therefore no derive key
        password_obj.set_password(&password).unwrap();
        
        self.passwords.insert(website, password_obj);
    }

    pub fn save_to_file(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json.as_bytes())
    }

    pub fn load_from_file(path: &Path) -> io::Result<Self> {
        let json_string = fs::read_to_string(path).map_err(|e| io::Error::other(e))?;
        let user = serde_json::from_str(&json_string).map_err(|e| io::Error::other(e))?;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::authentication::user::User;

    #[test]
    fn instance_user() {
        let _user = User::new(None, None);
    }

    #[test]
    fn set_password_test() {
        let mut user = User::new(None, None);
        user.set_password("Hello world!");
    }

    #[test]
    fn verify_password_test() {
        let salt = "de9488b19b6d97136a0e549885212e23";
        let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$wc/PuDAjnSqqAOXdV6+P8w$fF33+MWQ5/N+xQjdSKw0sdMEMLpzB4B5TBd2uPxQO3A";
        let mut user = User::new(Some(password_hash.to_string()), Some(salt.to_string()));
        user.verify_hash("Hello world!");
        assert!(user.derived_key.is_some());
    }
    #[test]
    fn derive_key_test() {
        let salt = "de9488b19b6d97136a0e549885212e23";
        let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$wc/PuDAjnSqqAOXdV6+P8w$fF33+MWQ5/N+xQjdSKw0sdMEMLpzB4B5TBd2uPxQO3A";
        let key = "620eb6e04c46083f99afe1208a306a27584e444ce4b557fcc4cb20d7b0a56ca9";
        let mut user = User::new(Some(password_hash.to_string()), Some(salt.to_string()));
        user.verify_hash("Hello world!");
        assert_eq!(key.to_string(), hex::encode(user.derived_key.unwrap()));
    }

    #[test]
    fn add_password_test() {
        let salt = "de9488b19b6d97136a0e549885212e23";
        let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$wc/PuDAjnSqqAOXdV6+P8w$fF33+MWQ5/N+xQjdSKw0sdMEMLpzB4B5TBd2uPxQO3A";
        let key = "620eb6e04c46083f99afe1208a306a27584e444ce4b557fcc4cb20d7b0a56ca9";
        let mut user = User::new(Some(password_hash.to_string()), Some(salt.to_string()));
        user.verify_hash("Hello world!");
        user.add_password("test.com".to_string(), "Hello123".to_string(), "12342".to_string());
        assert_eq!(key.to_string(), hex::encode(user.derived_key.unwrap()));
    }
    
    #[test]
    fn save_and_load_user() {

        // Create temp directory
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("user.json");
        
        // Create user
        let mut user = User::new(None, None);
        user.set_password("Hello world!");
        user.add_password(
            "example.com".to_string(),
            "Secret123".to_string(),
            "username".to_string(),
        );
    
        // Save user
        user.save_to_file(&file_path).unwrap();
    
        // Load user
        let loaded_user = User::load_from_file(&file_path).unwrap();
    
        // Assertions
        assert!(loaded_user.password_hash.is_some());
        assert!(loaded_user.derived_salt.is_some());
    
        // derived_key should NOT be saved
        assert!(loaded_user.derived_key.is_none());
    
        // passwords should persist
        assert!(loaded_user.passwords.contains_key("example.com"));
}

}