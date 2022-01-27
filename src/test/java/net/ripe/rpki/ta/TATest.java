package net.ripe.rpki.ta;


import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class TATest {

    @Test
    public void initialise_ta() throws Exception {
        final TAState taState = new TA(Env.local()).initialiseTaState();
        assertEquals(Env.local(), taState.getConfig());
        assertNotNull(taState.getEncoded());
    }

    @Test
    public void serialize_ta() throws Exception {
        final String HOME = System.getProperty("user.home");

        final String xml = TA.serialize(new TA(Env.local()).initialiseTaState());
        assertTrue(xml.contains("<taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>"));
        assertTrue(xml.contains("<taProductsPublicationUri>rsync://localhost:10873/repository/</taProductsPublicationUri>"));
        assertTrue(xml.contains("<keystoreProvider>SUN</keystoreProvider>"));
        assertTrue(xml.contains("<keypairGeneratorProvider>SunRsaSign</keypairGeneratorProvider>"));
        assertTrue(xml.contains("<signatureProvider>SunRsaSign</signatureProvider>"));
        assertTrue(xml.contains("<keystoreType>JKS</keystoreType>"));
        // Constructed differently from implementation
        assertTrue(xml.contains("<persistentStorageDir>" + HOME + "/export/bad/certification/ta/data</persistentStorageDir>"));
        assertTrue(xml.contains("<minimumValidityPeriod>P1M</minimumValidityPeriod>"));
        assertTrue(xml.contains("<updatePeriod>P3M</updatePeriod>"));
        assertTrue(xml.contains("<keyStorePassphrase>"));
        assertTrue(xml.contains("</keyStorePassphrase>"));
        assertTrue(xml.contains("<keyStoreKeyAlias>"));
        assertTrue(xml.contains("</keyStoreKeyAlias>"));
        assertTrue(xml.startsWith("<TA>"));
        assertTrue(xml.endsWith("</TA>"));
    }

}
