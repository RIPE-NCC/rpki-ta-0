package net.ripe.rpki.ta.serializers.legacy;


import lombok.EqualsAndHashCode;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;

import java.math.BigInteger;

// Do not move from `legacy` folder because qualified name is used in the XML files.
@EqualsAndHashCode(callSuper = true)
public class SignedResourceCertificate extends SignedObjectTracker {
    private static final long serialVersionUID = 1L;

    public SignedResourceCertificate(String fileName, X509ResourceCertificate resourceCertificate) {
        super(fileName, resourceCertificate, resourceCertificate.getValidityPeriod().getNotValidAfter());
    }

    public X509ResourceCertificate getResourceCertificate() {
        return (X509ResourceCertificate) getCertificateRepositoryObject();
    }

    @Override
    public BigInteger getCertificateSerial() {
        X509ResourceCertificate resourceCertificate = (X509ResourceCertificate) getCertificateRepositoryObject();
        return resourceCertificate.getSerialNumber();
    }
}
