package net.ripe.rpki.ta;

/*-
 * ========================LICENSE_START=================================
 * RIPE NCC Trust Anchor
 * -
 * Copyright (C) 2017 RIPE NCC
 * -
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the RIPE NCC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * =========================LICENSE_END==================================
 */

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
