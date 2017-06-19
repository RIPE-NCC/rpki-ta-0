package net.ripe.rpki.ta.domain;

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

import net.ripe.rpki.ta.config.Config;

import java.math.BigInteger;
import java.util.List;

public class TAStateBuilder {

    private final TAState taState;

    public TAStateBuilder(Config config) {
        taState = new TAState();
        taState.setConfig(config);
    }

    public TAStateBuilder withEncoded(byte[] encoded) {
        taState.setEncoded(encoded);
        return this;
    }

    public TAStateBuilder withKeyStoreKeyAlias(String keyStoreKeyAlias) {
        taState.setKeyStoreKeyAlias(keyStoreKeyAlias);
        return this;
    }

    public TAStateBuilder withKeyStorePassphrase(String keyStorePassphrase) {
        taState.setKeyStorePassphrase(keyStorePassphrase);
        return this;
    }

    public TAStateBuilder withLastIssuedCertificateSerial(BigInteger lastIssuedCertificateSerial) {
        taState.setLastIssuedCertificateSerial(lastIssuedCertificateSerial);
        return this;
    }

    public TAStateBuilder withSignedProductionCertificates(List<SignedResourceCertificate> signedProductionCertificates) {
        taState.setSignedProductionCertificates(signedProductionCertificates);
        return this;
    }

    public TAStateBuilder withSignedManifests(List<SignedManifest> signedManifests) {
        taState.setSignedManifests(signedManifests);
        return this;
    }

    public TAStateBuilder withLastCrlAndManifestNumber(BigInteger lastCrlAndManifestNumber) {
        taState.setLastCrlAndManifestNumber(lastCrlAndManifestNumber);
        return this;
    }

    public TAState build() {
        return taState;
    }
}
