package net.ripe.rpki.ta.util;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.ta.config.Config;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class ValidityPeriods {

    private static final int TA_CERTIFICATE_VALIDITY_TIME_IN_MONTHS = 6;

    // Since this program runs within a script, we can safely assume that all
    // calls to "now" can be replaced with a value calculated only once.
    private static final DateTime globalNow = DateTime.now(DateTimeZone.UTC);

    public static DateTime now() {
        return globalNow;
    }

    private final Config config;

    public ValidityPeriods(Config config) {
        this.config = config;
    }

    public ValidityPeriod allResourcesCertificate() {
        final DateTime notValidBefore = ValidityPeriods.now();
        return new ValidityPeriod(notValidBefore, calculateTaCertValidityNotAfter(notValidBefore));
    }

    public static ValidityPeriod taCertificate() {
        final DateTime notValidBefore = ValidityPeriods.now();
        return new ValidityPeriod(notValidBefore, notValidBefore.plusMonths(TA_CERTIFICATE_VALIDITY_TIME_IN_MONTHS));
    }

    public ValidityPeriod crl() {
        return cmsValidityPeriod();
    }

    public ValidityPeriod manifest() {
        return cmsValidityPeriod();
    }

    public ValidityPeriod eeCert() {
        return cmsValidityPeriod();
    }

    private ValidityPeriod cmsValidityPeriod() {
        final DateTime thisUpdateTime = ValidityPeriods.now();
        final DateTime nextUpdateTime = calculateNextUpdateTime(thisUpdateTime);
        return new ValidityPeriod(thisUpdateTime, nextUpdateTime);
    }

    /**
     * Set end of validity period to 1st of July next year.
     */
    private static DateTime calculateTaCertValidityNotAfter(final DateTime dateTime) {
        return new DateTime(dateTime.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC).plusMonths(6);
    }

    private DateTime calculateNextUpdateTime(final DateTime now) {
        final DateTime minimum = now.plus(config.getMinimumValidityPeriod());
        DateTime result = now;
        while (result.isBefore(minimum)) {
            result = result.plus(config.getUpdatePeriod());
        }
        return result;
    }
}
