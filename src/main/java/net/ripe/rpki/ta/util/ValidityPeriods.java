package net.ripe.rpki.ta.util;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsBuilder;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.x509cert.RpkiSignedObjectEeCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.ta.config.Config;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class ValidityPeriods {

    private static final int TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS = 100;

    static DateTime globalNow;

    // Since this program runs within a script, we can safely assume that all
    // calls to "now" can be replaced with a value calculated only once.
    public static synchronized DateTime now() {
        if (globalNow == null) {
            globalNow = DateTime.now(DateTimeZone.UTC);
        }
        return globalNow;
    }

    public static ManifestCmsBuilder manifestBuilder(Config config) {
        final ManifestCmsBuilder builder = new ManifestCmsBuilder();
        final DateTime thisUpdateTime = ValidityPeriods.now();
        final DateTime nextUpdateTime = calculateNextUpdateTime(config, thisUpdateTime);
        return builder
                .withNextUpdateTime(nextUpdateTime)
                .withThisUpdateTime(thisUpdateTime);
    }

    public static RpkiSignedObjectEeCertificateBuilder eeCertBuilder(Config config) {
        final RpkiSignedObjectEeCertificateBuilder builder = new RpkiSignedObjectEeCertificateBuilder();
        final DateTime thisUpdateTime = ValidityPeriods.now();
        final DateTime nextUpdateTime = calculateNextUpdateTime(config, thisUpdateTime);
        builder.withValidityPeriod(new ValidityPeriod(thisUpdateTime, nextUpdateTime));
        return builder;
    }

    public static X509ResourceCertificateBuilder allResourcesCertificateBuilder() {
        final X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        final DateTime notValidBefore = ValidityPeriods.now();
        return builder.withValidityPeriod(new ValidityPeriod(notValidBefore, calculateTaCertValidityNotAfter(notValidBefore)));
    }

    public static X509ResourceCertificateBuilder taCertificateBuilder() {
        final X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        final DateTime notValidBefore = ValidityPeriods.now();
        return builder.withValidityPeriod(new ValidityPeriod(notValidBefore, notValidBefore.plusYears(TA_CERTIFICATE_VALIDITY_TIME_IN_YEARS)));
    }

    /**
     * Set end of validity period to 1st of July next year.
     */
    private static DateTime calculateTaCertValidityNotAfter(final DateTime dateTime) {
        return new DateTime(dateTime.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC).plusMonths(6);
    }

    private static DateTime calculateNextUpdateTime(Config config, final DateTime now) {
        final DateTime minimum = now.plus(config.getMinimumValidityPeriod());
        DateTime result = now;
        while (result.isBefore(minimum)) {
            result = result.plus(config.getUpdatePeriod());
        }
        return result;
    }

    public static X509CrlBuilder crlBuilder(Config config) {
        final DateTime thisUpdateTime = ValidityPeriods.now();
        return new X509CrlBuilder()
                .withThisUpdateTime(thisUpdateTime)
                .withNextUpdateTime(calculateNextUpdateTime(config, thisUpdateTime));
    }
}
