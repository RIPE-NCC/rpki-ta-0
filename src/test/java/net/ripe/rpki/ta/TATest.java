package net.ripe.rpki.ta;

import net.ripe.rpki.ta.config.Env;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TATest {
    @Test
    public void initialise_ta() throws Exception {
        final TA ta = TA.initialise(Env.local());
        assertThat(Env.local()).isEqualTo(ta.getState().getConfig());
        assertThat(ta.getState().getEncoded()).isNotNull();
    }

    @Test
    public void serialize_ta() throws Exception {
        final String HOME = System.getProperty("user.home");

        final String xml = TA.initialise(Env.local()).serialize();
        assertThat(xml).contains("<taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>");
        assertThat(xml).contains("<taProductsPublicationUri>rsync://localhost:10873/repository/</taProductsPublicationUri>");
        assertThat(xml).contains("<keystoreProvider>SUN</keystoreProvider>");
        assertThat(xml).contains("<keypairGeneratorProvider>SunRsaSign</keypairGeneratorProvider>");
        assertThat(xml).contains("<signatureProvider>SunRsaSign</signatureProvider>");
        assertThat(xml).contains("<keystoreType>JKS</keystoreType>");
        // Constructed differently from implementation
        assertThat(xml).contains("<persistentStorageDir>" + HOME + "/export/bad/certification/ta/data</persistentStorageDir>");
        assertThat(xml).contains("<minimumValidityPeriod>P1M</minimumValidityPeriod>");
        assertThat(xml).contains("<updatePeriod>P3M</updatePeriod>");
        assertThat(xml).contains("<keyStorePassphrase>");
        assertThat(xml).contains("</keyStorePassphrase>");
        assertThat(xml).contains("<keyStoreKeyAlias>");
        assertThat(xml).contains("</keyStoreKeyAlias>");
        assertThat(xml).startsWith("<TA>");
        assertThat(xml).endsWith("</TA>");
    }

}
