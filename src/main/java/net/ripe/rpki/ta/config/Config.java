package net.ripe.rpki.ta.config;

import com.google.common.base.Preconditions;
import lombok.*;
import net.ripe.rpki.ta.util.ValidityPeriods;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

@Getter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
public class Config {
    @Setter
    private X500Principal trustAnchorName;

    @Setter
    private String keystoreProvider;

    @Setter
    private String keypairGeneratorProvider;

    @Setter
    private String signatureProvider;

    @Setter
    private String keystoreType;

    @Setter
    private String persistentStorageDir;

    @Setter
    private URI taCertificatePublicationUri;

    @Setter
    private URI taProductsPublicationUri;

    @Setter
    private URI notificationUri;

    private Period minimumValidityPeriod;

    private Period taCertificateValidityPeriod;

    private final String minimalValidityErrorMessage = "Minimum validity period cannot be null";

    // Do not allow validity periods of less than three months for TA certificates.
    // Smaller values may appear because of the configuration already stored in the
    // persistent state of the TA.
    public synchronized Period getTaCertificateValidityPeriod() {
        var threeMonths = Period.months(3);
        if (taCertificateValidityPeriod == null) {
            taCertificateValidityPeriod = threeMonths;
        } else {
            var now = ValidityPeriods.now();
            if (now.plus(taCertificateValidityPeriod).isBefore(now.plus(threeMonths))) {
                taCertificateValidityPeriod = threeMonths;
            }
        }
        return taCertificateValidityPeriod;
    }

    public Period getMinimumValidityPeriod() {
        return Preconditions.checkNotNull(minimumValidityPeriod, minimalValidityErrorMessage);
    }

    public void setMinimumValidityPeriod(Period minimumValidityPeriod) {
        this.minimumValidityPeriod = Preconditions.checkNotNull(minimumValidityPeriod, minimalValidityErrorMessage);
    }

}
