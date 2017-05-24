package net.ripe.rpki.ta.config;


import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.net.URI;

public class Env {

    public static Config config(String envName) throws Exception {
        if ("development".equals(envName)) {
            return development();
        } else if ("production".equals(envName)) {
            return production();
        } else {
            throw new Exception("Unknow environemt name: " + envName);
        }
    }

    public static Config production() {
        Config config = new Config();
        config.setSignatureProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeystoreType("ncipher.sworld");
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("ripe-ncc-ta"));
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.ripe.net/repository/"));
        return config;
    }

    public static Config development() {
        Config config = new Config();
        config.setSignatureProvider("SunRsaSign");
        config.setKeystoreProvider("SunRsaSign");
        config.setKeystoreProvider("SUN");
        config.setKeystoreType("JKS");
        config.setTrustAnchorName(new X500Principal("CN=RIPE-NCC-TA-" + new DateTime(DateTimeZone.UTC).toString("YYYY-MM-dd")));
        config.setPersistentStorageDir("/export/bad/certification/ta/data");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("ripe-ncc-ta"));
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/online/"));
        return config;
    }
}
