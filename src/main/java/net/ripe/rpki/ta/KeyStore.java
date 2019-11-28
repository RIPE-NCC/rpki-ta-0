package net.ripe.rpki.ta;


import com.google.common.io.Closer;
import net.ripe.rpki.commons.crypto.util.KeyStoreException;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;

class KeyStore {

    private static final String KEY_STORE_KEY_ALIAS = "RTA2";
    private static final char[] KEY_STORE_PASS_PHRASE = "2fe5a028-861a-47a0-a27f-7c657ea6ed49".toCharArray();

    private final String keyStoreKeyAlias;
    private final char[] keyStorePassPhrase;

    private final Config config;

    KeyStore(Config config, String keyStoreKeyAlias, char[] keyStorePassPhrase) {
        this.config = config;
        this.keyStoreKeyAlias = keyStoreKeyAlias;
        this.keyStorePassPhrase = keyStorePassPhrase;
    }

    byte[] encode(final KeyPair keyPair, final X509ResourceCertificate taCertificate) throws Exception {
        return encodeKeyStore(createKeyStore(keyPair, taCertificate));
    }

    private java.security.KeyStore createKeyStore(final KeyPair keyPair, final X509ResourceCertificate taCertificate) {
        try {
            final java.security.KeyStore ks = loadKeyStore(null, keyStorePassPhrase);
            final Certificate[] certificates = new Certificate[] { taCertificate.getCertificate() };
            ks.setKeyEntry(keyStoreKeyAlias, keyPair.getPrivate(), keyStorePassPhrase, certificates);
            return ks;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }
    }

    private java.security.KeyStore loadKeyStore(final InputStream input, char[] password) throws GeneralSecurityException, IOException {
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(config.getKeystoreType(), config.getKeystoreProvider());
        keyStore.load(input, password);
        return keyStore;
    }

    private byte[] encodeKeyStore(java.security.KeyStore keyStore) throws Exception {
        final Closer closer = Closer.create();
        try {
            final ByteArrayOutputStream output = closer.register(new ByteArrayOutputStream());
            keyStore.store(output, keyStorePassPhrase);
            return output.toByteArray();
        } catch (final Throwable t) {
            throw closer.rethrow(t, GeneralSecurityException.class);
        } finally {
            closer.close();
        }
    }

    Pair<KeyPair, X509ResourceCertificate> decode(byte[] encoded) throws Exception {
        final Closer closer = Closer.create();
        try {
            final ByteArrayInputStream input = closer.register(new ByteArrayInputStream(encoded));
            final java.security.KeyStore keyStore = loadKeyStore(input, keyStorePassPhrase);
            final PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreKeyAlias, keyStorePassPhrase);
            Validate.notNull(privateKey, "private key is null");
            final Certificate certificate = keyStore.getCertificateChain(keyStoreKeyAlias)[0];
            final X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse("keystore", certificate.getEncoded());

            final X509ResourceCertificate taCertificate = parser.getCertificate();
            final KeyPair keyPair = new KeyPair(taCertificate.getPublicKey(), privateKey);
            return ImmutablePair.of(keyPair, taCertificate);

        } catch (final Throwable t) {
            throw closer.rethrow(t, GeneralSecurityException.class);
        } finally {
            closer.close();
        }
    }

    static KeyStore of(final Config config) {
        return new KeyStore(config, KEY_STORE_KEY_ALIAS, KEY_STORE_PASS_PHRASE);
    }

    static KeyStore legacy(final Config config) {
        return new KeyStore(config, LegacyTA.KEY_STORE_ALIAS, LegacyTA.KEY_STORE_PASSPHRASE);
    }

    public String getKeyStoreKeyAlias() {
        return keyStoreKeyAlias;
    }

    public String getKeyStorePassPhrase() {
        return new String(keyStorePassPhrase);
    }
}
