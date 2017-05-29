package net.ripe.rpki.ta;

import com.google.common.io.Closer;
import net.ripe.rpki.commons.crypto.util.KeyStoreException;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.ta.config.Config;
import org.apache.commons.lang.Validate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyStore {

    private final char[] keyStorePassphrase = "68f2d230-ba89-49d8-9578-83aea34f8817".toCharArray();
    private final String keyStoreKeyAlias = "RTA"; //(mj) changing the alias means keystore migration!

    private X509ResourceCertificate taCertificate;
    private KeyPair keyPair;
    private byte[] encoded;

    private final Config config;

    public KeyStore(Config config) {
        this.config = config;
    }

    public void save(final KeyPair keyPair, final X509ResourceCertificate taCertificate) {

    }

    private void createKeyStore() {
        try {
            java.security.KeyStore keyStore = generateKeyStore();
            encodeKeyStore(keyStore);
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException(e);
        } catch (IOException e) {
            throw new KeyStoreException(e);
        }
    }

    private java.security.KeyStore generateKeyStore() throws GeneralSecurityException, IOException {
        java.security.KeyStore keyStore = loadKeyStore(null, keyStorePassphrase); // empty, initialized key store
        keyStore.setKeyEntry(keyStoreKeyAlias, keyPair.getPrivate(), keyStorePassphrase, new Certificate[] { taCertificate.getCertificate() });
        return keyStore;
    }

    private java.security.KeyStore loadKeyStore(InputStream input, char[] password) throws GeneralSecurityException, IOException {
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance(config.getKeystoreType(), config.getKeystoreProvider());
        keyStore.load(input, password);
        return keyStore;
    }

    private void encodeKeyStore(java.security.KeyStore keyStore) throws GeneralSecurityException, IOException {
        final Closer closer = Closer.create();
        try {
            final ByteArrayOutputStream output = closer.register(new ByteArrayOutputStream());
            keyStore.store(output, keyStorePassphrase);
            this.encoded = output.toByteArray();
        } catch (final Throwable t) {
            throw closer.rethrow(t, GeneralSecurityException.class);
        } finally {
            closer.close();
        }
    }

    public void open() {
        Validate.notNull(encoded, "encoded is null");
        try {
            decodeKeyStore();
        } catch (GeneralSecurityException ex) {
            throw new KeyStoreException(ex);
        } catch (IOException ex) {
            throw new KeyStoreException(ex);
        }
    }

    private void decodeKeyStore() throws GeneralSecurityException, IOException {
        final Closer closer = Closer.create();
        try {
            final ByteArrayInputStream input = closer.register(new ByteArrayInputStream(encoded));
            java.security.KeyStore keyStore = loadKeyStore(input, keyStorePassphrase);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStoreKeyAlias, keyStorePassphrase);
            Validate.notNull(privateKey, "private key is null");
            Certificate certificate = keyStore.getCertificateChain(keyStoreKeyAlias)[0];
            X509ResourceCertificateParser parser = new X509ResourceCertificateParser();
            parser.parse("keystore", certificate.getEncoded());
            this.taCertificate = parser.getCertificate();
            this.keyPair = new KeyPair(taCertificate.getPublicKey(), privateKey);
        } catch (final Throwable t) {
            throw closer.rethrow(t, GeneralSecurityException.class);
        } finally {
            closer.close();
        }
    }


}
