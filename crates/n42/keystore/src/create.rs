use serde::{Deserialize, Serialize};
use crate::keystore::{JsonWallet, ValidatorKeystores, Error, KeyType, Keystore,
                      recover_validator_secret, PlainText, keypair_from_secret, decrypt, KeystoreBuilder};



#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Wallet {
    json: JsonWallet,
}

impl Wallet {
    /// Produces a `Keystore`
    pub fn next_validator(
        &mut self,
        wallet_password: &[u8],
        voting_keystore_password: &[u8],
        withdrawal_keystore_password: &[u8],
    ) -> Result<ValidatorKeystores, Error> {
        // Helper closure to reduce code duplication when generating keys.
        //
        // It is not a function on `self` to help protect against generating keys without
        // incrementing `nextaccount`.
        let derive = |key_type: KeyType, password: &[u8]| -> Result<Keystore, Error> {
            let (secret, path) =
                recover_validator_secret(self, wallet_password, self.json.nextaccount, key_type)?;

            let keypair = keypair_from_secret(secret.as_bytes())?;

            KeystoreBuilder::new(&keypair, password, format!("{}", path))?
                .build()
                .map_err(Into::into)
        };

        let keystores = ValidatorKeystores {
            voting: derive(KeyType::Voting, voting_keystore_password)?,
            withdrawal: derive(KeyType::Withdrawal, withdrawal_keystore_password)?,
        };

        self.json.nextaccount = self
            .json
            .nextaccount
            .checked_add(1)
            .ok_or(Error::PathExhausted)?;

        Ok(keystores)
    }

    /// Returns the master seed of this wallet. Care should be taken not to leak this seed.
    pub fn decrypt_seed(&self, password: &[u8]) -> Result<PlainText, Error> {
        decrypt(password, &self.json.crypto).map_err(Into::into)
    }
}