package net.ripe.rpki.ta.serializers.legacy;

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

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.util.KeyPairFactory;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to read old style TA.
 */
public class LegacyTA {

    private transient KeyPair caKeyPair;

    private URI taCertificatePublicationUri;
    private URI taProductsPublicationUri;

    private X500Principal caName;
    private Period crlMinimumValidityPeriod;
    private Period crlUpdatePeriod;
    private X509Crl crl;
    private BigInteger lastCrlNumber;

    private String signatureProvider;
    private transient KeyPairFactory keyPairFactory;

    private TrustAnchorKeyStore trustAnchorKeyStore;
    private List<SignedResourceCertificate> previousTaCertificates = new ArrayList<SignedResourceCertificate>();
    private List<SignedResourceCertificate> signedProductionCertificates = new ArrayList<SignedResourceCertificate>();

    private List<SignedManifest> signedManifests = new ArrayList<SignedManifest>();
    private ManifestCms manifest;

    private BigInteger lastManifestNumber = BigInteger.ZERO;

    private BigInteger lastIssuedCertificateSerial;
    private Long lastProcessedRequestTimestamp;

    public KeyPair getCaKeyPair() {
        return caKeyPair;
    }

    public URI getTaCertificatePublicationUri() {
        return taCertificatePublicationUri;
    }

    public URI getTaProductsPublicationUri() {
        return taProductsPublicationUri;
    }

    public X500Principal getCaName() {
        return caName;
    }

    public Period getCrlMinimumValidityPeriod() {
        return crlMinimumValidityPeriod;
    }

    public Period getCrlUpdatePeriod() {
        return crlUpdatePeriod;
    }

    public X509Crl getCrl() {
        return crl;
    }

    public BigInteger getLastCrlNumber() {
        return lastCrlNumber;
    }

    public String getSignatureProvider() {
        return signatureProvider;
    }

    public KeyPairFactory getKeyPairFactory() {
        return keyPairFactory;
    }

    public TrustAnchorKeyStore getTrustAnchorKeyStore() {
        return trustAnchorKeyStore;
    }

    public List<SignedResourceCertificate> getPreviousTaCertificates() {
        return previousTaCertificates;
    }

    public List<SignedResourceCertificate> getSignedProductionCertificates() {
        return signedProductionCertificates;
    }

    public List<SignedManifest> getSignedManifests() {
        return signedManifests;
    }

    public ManifestCms getManifest() {
        return manifest;
    }

    public BigInteger getLastManifestNumber() {
        return lastManifestNumber;
    }

    public BigInteger getLastIssuedCertificateSerial() {
        return lastIssuedCertificateSerial;
    }

    public Long getLastProcessedRequestTimestamp() {
        return lastProcessedRequestTimestamp;
    }
}
