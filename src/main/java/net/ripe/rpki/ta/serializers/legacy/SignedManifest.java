package net.ripe.rpki.ta.serializers.legacy;


import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;

import java.math.BigInteger;

public class SignedManifest extends SignedObjectTracker {

    public SignedManifest(ManifestCms manifestCms) {
        super(manifestCms, manifestCms.getValidityPeriod().getNotValidAfter());
    }

    public ManifestCms getManifest() {
        return (ManifestCms) getCertificateRepositoryObject();
    }

    @Override
    public BigInteger getCertificateSerial() {
        ManifestCms manifest = (ManifestCms) getCertificateRepositoryObject();
        return manifest.getCertificate().getSerialNumber();
    }
}
