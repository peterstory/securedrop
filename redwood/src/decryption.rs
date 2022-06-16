//! Decryption is much more complicated than encryption,
//! This code is mostly lifted from https://docs.sequoia-pgp.org/sequoia_guide/chapter_02/index.html

use sequoia_openpgp::crypto::{Password, SessionKey};
use sequoia_openpgp::parse::stream::*;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::types::SymmetricAlgorithm;

pub(crate) struct Helper<'a> {
    pub(crate) policy: &'a dyn Policy,
    pub(crate) secret: &'a sequoia_openpgp::Cert,
    pub(crate) passphrase: &'a Password,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        _ids: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        // Return public keys for signature verification here.
        Ok(Vec::new())
    }

    fn check(
        &mut self,
        _structure: MessageStructure,
    ) -> sequoia_openpgp::Result<()> {
        // Implement your signature verification policy here.
        Ok(())
    }
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        // The encryption key is the first and only subkey.
        let key = self
            .secret
            .keys()
            .secret()
            .with_policy(self.policy, None)
            .next()
            // FIXME: unwrap()
            .unwrap()
            .key()
            .clone();

        // Decrypt the secret key with the specified passphrase.
        let mut pair = key.decrypt_secret(self.passphrase)?.into_keypair()?;

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}
