/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
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

public class KeyStore {

    private static final String KEY_STORE_KEY_ALIAS = "RTA2";
    /**
     * This passphrase only applies to trust anchor XML files using <b>software keys</b>.
     *
     * This passphrase is <b>not appplicable</b> for the production keys stored in the HSMs.
     * For the trust anchor HSMs, we use Operator Card Set protected keys. Multiple operator card holders need to be
     * present and enter the passphrase for their operator card to load the key into the HSM.
     *
     * This software is not used for the online HSMs.
     */
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

    public Pair<KeyPair, X509ResourceCertificate> decode(byte[] encoded) throws Exception {
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

    public static KeyStore of(final Config config) {
        return new KeyStore(config, KEY_STORE_KEY_ALIAS, KEY_STORE_PASS_PHRASE);
    }

    static KeyStore legacy(final Config config) {
        return new KeyStore(config, LegacyTA.KEY_STORE_ALIAS, LegacyTA.SOFTWARE_KEY_STORE_PASSPHRASE);
    }

    public String getKeyStoreKeyAlias() {
        return keyStoreKeyAlias;
    }

    public String getKeyStorePassPhrase() {
        return new String(keyStorePassPhrase);
    }
}
