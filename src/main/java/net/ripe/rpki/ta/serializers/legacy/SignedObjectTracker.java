package net.ripe.rpki.ta.serializers.legacy;

import lombok.Getter;
import lombok.ToString;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.ta.util.ValidityPeriods;
import org.apache.commons.lang3.Validate;
import org.joda.time.DateTime;

import java.io.Serializable;
import java.math.BigInteger;

@ToString
@Getter
public abstract class SignedObjectTracker implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String fileName;
    private final CertificateRepositoryObject certificateRepositoryObject;
    private final DateTime notValidAfter;
    private DateTime revocationTime;

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

    public void revoke() {
        if (revocationTime == null) {
            revocationTime = ValidityPeriods.now();
        }
    }

    public boolean shouldAppearInCrl() {
        return (isRevoked() && !isExpired());
    }

    public boolean isPublishable() {
        return !isExpired() && !isRevoked();
    }

    private boolean isExpired() {
        return ValidityPeriods.now().isAfter(notValidAfter);
    }

    public boolean isRevoked() {
        return revocationTime != null;
    }

    public abstract BigInteger getCertificateSerial();
}
