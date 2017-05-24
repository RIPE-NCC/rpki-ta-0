package net.ripe.rpki.ta.config;

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

import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class Config {

    private X500Principal trustAnchorName;
    private URI taCertificatePublicationUri;
    private URI taProductsPublicationUri;
    private String keystoreProvider;
    private String keypairGeneratorProvider;
    private String signatureProvider;
    private String keystoreType;
    private String persistentStorageDir;
    private Period minimumValidityPeriod;
    private Period updatePeriod;

    public Config() {
    }

    public X500Principal getTrustAnchorName() {
        return trustAnchorName;
    }

    public void setTrustAnchorName(X500Principal trustAnchorName) {
        this.trustAnchorName = trustAnchorName;
    }

    public URI getTaCertificatePublicationUri() {
        return taCertificatePublicationUri;
    }

    public void setTaCertificatePublicationUri(URI taCertificatePublicationUri) {
        this.taCertificatePublicationUri = taCertificatePublicationUri;
    }

    public String getKeystoreProvider() {
        return keystoreProvider;
    }

    public void setKeystoreProvider(String keystoreProvider) {
        this.keystoreProvider = keystoreProvider;
    }

    public String getKeypairGeneratorProvider() {
        return keypairGeneratorProvider;
    }

    public void setKeypairGeneratorProvider(String keypairGeneratorProvider) {
        this.keypairGeneratorProvider = keypairGeneratorProvider;
    }

    public String getSignatureProvider() {
        return signatureProvider;
    }

    public void setSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
    }

    public String getKeystoreType() {
        return keystoreType;
    }

    public void setKeystoreType(String keystoreType) {
        this.keystoreType = keystoreType;
    }

    public String getPersistentStorageDir() {
        return persistentStorageDir;
    }

    public void setPersistentStorageDir(String persistentStorageDir) {
        this.persistentStorageDir = persistentStorageDir;
    }

    public Period getMinimumValidityPeriod() {
        return minimumValidityPeriod;
    }

    public void setMinimumValidityPeriod(Period minimumValidityPeriod) {
        this.minimumValidityPeriod = minimumValidityPeriod;
    }

    public Period getUpdatePeriod() {
        return updatePeriod;
    }

    public void setUpdatePeriod(Period updatePeriod) {
        this.updatePeriod = updatePeriod;
    }

    public URI getTaProductsPublicationUri() {
        return taProductsPublicationUri;
    }

    public void setTaProductsPublicationUri(URI taProductsPublicationUri) {
        this.taProductsPublicationUri = taProductsPublicationUri;
    }
}
