package net.ripe.rpki.ta.domain;

import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.ta.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.math.BigInteger;
import java.util.List;

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

/**
 * TA state to be serialized to ta.xml
 */
public class TAState {

    private byte[] encoded;
    private Config config;
    private X509Crl crl;

    private String keyStorePassphrase;
    private String keyStoreKeyAlias;

    private BigInteger lastIssuedCertificateSerial;

    private BigInteger lastCrlAndManifestNumber;

    private List<Revocation> revocations;

    public List<Revocation> getRevocations() {
        return revocations;
    }

    TAState() {
        // package protected constructor so XStream can instantiate this object
    }

    public TAState(Config config) {
        this.config = config;
    }

    void setRevocations(List<Revocation> revocations) {
        this.revocations = revocations;
    }

    public BigInteger getLastCrlAndManifestNumber() {
        return lastCrlAndManifestNumber;
    }

    void setLastCrlAndManifestNumber(BigInteger lastCrlAndManifestNumber) {
        this.lastCrlAndManifestNumber = lastCrlAndManifestNumber;
    }

    public X509Crl getCrl() {
        return crl;
    }

    void setCrl(X509Crl crl) {
        this.crl = crl;
    }

    public byte[] getEncoded() {
        return encoded;
    }

    void setEncoded(byte[] encoded) {
        this.encoded = encoded;
    }

    public Config getConfig() {
        return config;
    }

    void setConfig(Config config) {
        this.config = config;
    }

    public String getKeyStorePassphrase() {
        return keyStorePassphrase;
    }

    void setKeyStorePassphrase(String keyStorePassphrase) {
        this.keyStorePassphrase = keyStorePassphrase;
    }

    public String getKeyStoreKeyAlias() {
        return keyStoreKeyAlias;
    }

    void setKeyStoreKeyAlias(String keyStoreKeyAlias) {
        this.keyStoreKeyAlias = keyStoreKeyAlias;
    }

    public BigInteger getLastIssuedCertificateSerial() {
        return lastIssuedCertificateSerial;
    }

    void setLastIssuedCertificateSerial(BigInteger lastIssuedCertificateSerial) {
        this.lastIssuedCertificateSerial = lastIssuedCertificateSerial;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        TAState taState = (TAState) o;

        return new EqualsBuilder()
                .append(crl, taState.crl)
                .append(encoded, taState.encoded)
                .append(config, taState.config)
                .append(keyStorePassphrase, taState.keyStorePassphrase)
                .append(keyStoreKeyAlias, taState.keyStoreKeyAlias)
                .append(lastCrlAndManifestNumber, taState.lastCrlAndManifestNumber)
                .append(lastIssuedCertificateSerial, taState.lastIssuedCertificateSerial)
                .append(revocations, taState.revocations)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(crl)
                .append(encoded)
                .append(config)
                .append(keyStorePassphrase)
                .append(keyStoreKeyAlias)
                .append(lastCrlAndManifestNumber)
                .append(lastIssuedCertificateSerial)
                .append(revocations)
                .toHashCode();
    }

}
