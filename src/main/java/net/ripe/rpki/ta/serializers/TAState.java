package net.ripe.rpki.ta.serializers;

import net.ripe.rpki.ta.config.Config;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.math.BigInteger;

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

    private String keyStorePassphrase;
    private String keyStoreKeyAlias;

    private BigInteger lastIssuedCertificateSerial;

    public byte[] getEncoded() {
        return encoded;
    }

    public void setEncoded(byte[] encoded) {
        this.encoded = encoded;
    }

    public Config getConfig() {
        return config;
    }

    public void setConfig(Config config) {
        this.config = config;
    }

    public String getKeyStorePassphrase() {
        return keyStorePassphrase;
    }

    public void setKeyStorePassphrase(String keyStorePassphrase) {
        this.keyStorePassphrase = keyStorePassphrase;
    }

    public String getKeyStoreKeyAlias() {
        return keyStoreKeyAlias;
    }

    public void setKeyStoreKeyAlias(String keyStoreKeyAlias) {
        this.keyStoreKeyAlias = keyStoreKeyAlias;
    }

    public BigInteger getLastIssuedCertificateSerial() {
        return lastIssuedCertificateSerial;
    }

    public void setLastIssuedCertificateSerial(BigInteger lastIssuedCertificateSerial) {
        this.lastIssuedCertificateSerial = lastIssuedCertificateSerial;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;

        if (o == null || getClass() != o.getClass()) return false;

        TAState taState = (TAState) o;

        return new EqualsBuilder()
                .append(encoded, taState.encoded)
                .append(config, taState.config)
                .append(keyStorePassphrase, taState.keyStorePassphrase)
                .append(keyStoreKeyAlias, taState.keyStoreKeyAlias)
                .append(lastIssuedCertificateSerial, taState.lastIssuedCertificateSerial)
                .isEquals();
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37)
                .append(encoded)
                .append(config)
                .append(keyStorePassphrase)
                .append(keyStoreKeyAlias)
                .append(lastIssuedCertificateSerial)
                .toHashCode();
    }
}
