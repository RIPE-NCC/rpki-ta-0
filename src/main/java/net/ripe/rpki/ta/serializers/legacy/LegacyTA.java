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

import net.ripe.rpki.commons.crypto.crl.X509Crl;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to read old style TA.
 */
public class LegacyTA {

    // TODO Move this ones to ta.xml
    public static final String KEY_STORE_ALIAS = "RTA";
    public final static char[] KEY_STORE_PASSPHRASE = "68f2d230-ba89-49d8-9578-83aea34f8817".toCharArray();

    public TrustAnchorKeyStore getTrustAnchorKeyStore() {
        return trustAnchorKeyStore;
    }

    // We ignore everything, except for the old key pair
    private TrustAnchorKeyStore trustAnchorKeyStore;

    public BigInteger lastIssuedCertificateSerial;

    private BigInteger lastCrlNumber;

    private BigInteger lastManifestNumber;

    private List<SignedResourceCertificate> signedProductionCertificates = new ArrayList<SignedResourceCertificate>();

    public BigInteger getLastManifestNumber() {
        return lastManifestNumber;
    }

    public void setLastManifestNumber(BigInteger lastManifestNumber) {
        this.lastManifestNumber = lastManifestNumber;
    }

    public BigInteger getLastCrlNumber() {
        return lastCrlNumber;
    }

    public void setLastCrlNumber(BigInteger lastCrlNumber) {
        this.lastCrlNumber = lastCrlNumber;
    }

    private X509Crl crl;

    public X509Crl getCrl() {
        return crl;
    }

    public void setCrl(X509Crl crl) {
        this.crl = crl;
    }

    public List<SignedResourceCertificate> getSignedProductionCertificates() {
        return signedProductionCertificates;
    }

    public void setSignedProductionCertificates(List<SignedResourceCertificate> signedProductionCertificates) {
        this.signedProductionCertificates = signedProductionCertificates;
    }
}
