package net.ripe.rpki.ta;

import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TATest {
    @Test
    public void initialise_ta() throws Exception {
        final TAState taState = new TA(Env.local()).initialiseTaState();
        assertThat(Env.local()).isEqualTo(taState.getConfig());
        assertThat(taState.getEncoded()).isNotNull();
    }

    @Test
    public void serialize_ta() throws Exception {
        final String HOME = System.getProperty("user.home");

        final String xml = TA.serialize(new TA(Env.local()).initialiseTaState());
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
