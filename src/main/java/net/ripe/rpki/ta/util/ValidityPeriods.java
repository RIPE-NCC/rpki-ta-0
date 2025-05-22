package net.ripe.rpki.ta.util;

import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.ta.config.Config;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class ValidityPeriods {

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
        return new ValidityPeriod(notValidBefore, firstJulyNextYear(notValidBefore));
    }

    public ValidityPeriod taCertificate() {
        final DateTime notValidBefore = ValidityPeriods.now();
        final DateTime notValidAfter = notValidBefore.plus(config.getMinimumValidityPeriod().multipliedBy(2));
        return new ValidityPeriod(notValidBefore, notValidAfter);
    }

    public ValidityPeriod crl() {
        return cmsValidityPeriod();
    }

    public ValidityPeriod manifest() {
        return cmsValidityPeriod();
    }

    private ValidityPeriod cmsValidityPeriod() {
        final DateTime thisUpdateTime = ValidityPeriods.now();
        final DateTime nextUpdateTime = thisUpdateTime.plus(config.getMinimumValidityPeriod());
        return new ValidityPeriod(thisUpdateTime, nextUpdateTime);
    }

    private static DateTime firstJulyNextYear(final DateTime dateTime) {
        return new DateTime(dateTime.getYear() + 1, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC).plusMonths(6);
    }

}
