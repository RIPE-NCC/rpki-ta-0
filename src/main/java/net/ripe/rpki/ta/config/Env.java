package net.ripe.rpki.ta.config;



import lombok.experimental.UtilityClass;
import net.ripe.rpki.ta.exception.BadOptionsException;
import org.joda.time.Period;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;

@UtilityClass
public class Env {

    public static Config config(ProgramOptions options) throws BadOptionsException {
        final Config config = byEnvironment(options.getEnv());

        if (options.hasPersistentStoragePath()) {
            final File storageDirectory = new File(options.getPersistentStoragePath());
            if (!storageDirectory.isDirectory()) {
                throw new BadOptionsException(String.format("Persistent storage directory '%s' does not exist.", storageDirectory.getAbsolutePath()));
            }

            config.setPersistentStorageDir(storageDirectory.getAbsolutePath());
        }
        if (options.hasTaCertificatePublicationUri()) {
            config.setTaCertificatePublicationUri(tryParseUri(options.getTaCertificatePublicationUri()));
        }
        if (options.hasTaProductsPublicationUri()) {
            config.setTaProductsPublicationUri(tryParseUri(options.getTaProductsPublicationUri()));
        }
        if (options.hasNotificationUri()) {
            config.setNotificationUri(tryParseUri(options.getNotificationUri()));
        }

        return config;
    }

    private static URI tryParseUri(String uri) throws BadOptionsException {
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new BadOptionsException(String.format("Invalid URI: %s", uri));
        }
    }

    private static Config byEnvironment(String envName) throws BadOptionsException {
        if ("test".equals(envName)) {
            return EnvStub.test();
        }
        if (envName == null || "local".equals(envName)) {
            return local();
        }
        if ("dev".equals(envName)) {
            return dev();
        }
        if ("prepdev".equals(envName)) {
            return prepdev();
        }
        if ("pilot".equals(envName)) {
            return pilot();
        }
        if ("production".equals(envName)) {
            return production();
        }

        throw new BadOptionsException("Unknown environment name: " + envName);
    }

    public static Config production() {
        final Config config = nCipherConf();
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setMinimumValidityPeriod(Period.months(1));
        config.setUpdatePeriod(Period.months(3));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-ta"));
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.ripe.net/repository/"));
        config.setNotificationUri(URI.create("https://rrdp.ripe.net/notification.xml"));
        return config;
    }

    public static Config dev() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.dev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.dev.ripe.net/repository/"));
        return config;
    }

    public static Config prepdev() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://rpki.prepdev.ripe.net/repository/"));
        config.setNotificationUri(URI.create("https://rrdp.prepdev.ripe.net/notification.xml"));
        return config;
    }

    public static Config pilot() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setPersistentStorageDir("/export/bad/ta-ca/data/");
        config.setTaCertificatePublicationUri(URI.create("rsync://localcert.ripe.net/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localcert.ripe.net/repository/"));
        config.setTrustAnchorName(new X500Principal("CN=ripe-ncc-pilot"));
        config.setNotificationUri(URI.create("https://localcert.ripe.net/rrdp/notification.xml"));
        return config;
    }

    public static Config local() {
        final Config config = withSunRsaConf(EnvStub.testConfig());
        config.setTaCertificatePublicationUri(URI.create("rsync://localhost:10873/ta/"));
        config.setTaProductsPublicationUri(URI.create("rsync://localhost:10873/repository/"));
        return config;
    }

    private static Config nCipherConf() {
        return withNCipherConf(new Config());
    }

    private static Config withNCipherConf(final Config config) {
        config.setSignatureProvider("nCipherKM");
        config.setKeystoreProvider("nCipherKM");
        config.setKeypairGeneratorProvider("nCipherKM");
        config.setKeystoreType("ncipher.sworld");
        return config;
    }

    static Config withSunRsaConf(Config config) {
        config.setSignatureProvider("SunRsaSign");
        config.setKeystoreProvider("SUN");
        config.setKeypairGeneratorProvider("SunRsaSign");
        config.setKeystoreType("JKS");
        return config;
    }
}
