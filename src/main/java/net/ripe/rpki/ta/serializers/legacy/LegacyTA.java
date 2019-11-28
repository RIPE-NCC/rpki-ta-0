package net.ripe.rpki.ta.serializers.legacy;


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

    private List<SignedManifest> signedManifests;

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

    public List<SignedManifest> getSignedManifests() {
        return signedManifests;
    }

    public void setSignedManifests(List<SignedManifest> signedManifests) {
        this.signedManifests = signedManifests;
    }
}
