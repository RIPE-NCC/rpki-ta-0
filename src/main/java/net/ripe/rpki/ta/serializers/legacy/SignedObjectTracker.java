package net.ripe.rpki.ta.serializers.legacy;


import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import org.apache.commons.lang3.Validate;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.math.BigInteger;

public abstract class SignedObjectTracker implements Serializable {

    private static final long serialVersionUID = 1L;

    private final CertificateRepositoryObject certificateRepositoryObject;

    private final String fileName;

    private DateTime revocationTime;

    private DateTime notValidAfter;


    public SignedObjectTracker(CertificateRepositoryObject certificateRepositoryObject, DateTime notValidAfter) {
        Validate.notNull(certificateRepositoryObject, "certificateRepositoryObject is required");
        this.fileName = null;
        this.certificateRepositoryObject = certificateRepositoryObject;
        this.revocationTime = null;
        this.notValidAfter = notValidAfter;
    }

    public SignedObjectTracker(String fileName, CertificateRepositoryObject certificateRepositoryObject, DateTime notValidAfter) {
        Validate.notEmpty(fileName, "fileName is required");
        Validate.notNull(certificateRepositoryObject, "certificateRepositoryObject is required");
        this.fileName = fileName;
        this.certificateRepositoryObject = certificateRepositoryObject;
        this.revocationTime = null;
        this.notValidAfter = notValidAfter;
    }

    public String getFileName() {
        return fileName;
    }

    public CertificateRepositoryObject getCertificateRepositoryObject() {
        return certificateRepositoryObject;
    }

    public void revoke() {
        if (revocationTime == null) {
            revocationTime = now();
        }
    }

    public boolean shouldAppearInCrl() {
        return (isRevoked() && !isExpired());
    }

    public boolean isPublishable() {
        return !isExpired() && !isRevoked();
    }

    private boolean isExpired() {
        return now().isAfter(notValidAfter);
    }

    private DateTime now() {
        return DateTime.now(DateTimeZone.UTC);
    }

    public boolean isRevoked() {
        return revocationTime != null;
    }

    public DateTime getRevocationTime() {
        return revocationTime;
    }

    public abstract BigInteger getCertificateSerial();
}
