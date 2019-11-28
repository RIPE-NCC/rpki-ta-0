package net.ripe.rpki.ta.config;


import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class EnvStub {
    public static Config _testConfig = testConfig();

    static Config testConfig() {
        Config config = Env.sunRsaConf();
        config.setPersistentStorageDir("/export/bad/certification/ta/data");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("CN=RIPE-NCC-TA-TEST"));
        config.setNotificationUri(URI.create("https://rrdp.ripe.net/notification.xml"));
        return config;
    }

    public static Config getTestConfig() {
        return _testConfig;
    }

    public static Config test() {
        final Config config = getTestConfig();
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/online/"));
        return config;
    }
}
