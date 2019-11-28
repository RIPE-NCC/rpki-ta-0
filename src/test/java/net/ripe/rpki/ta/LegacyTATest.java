package net.ripe.rpki.ta;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.persistence.TAPersistence;
import net.ripe.rpki.ta.serializers.LegacyTASerializer;
import net.ripe.rpki.ta.serializers.TAStateSerializer;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.math.BigInteger;
import java.security.KeyPair;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


public class LegacyTATest {

    private static final String LEGACY_TA_PATH = "src/test/resources/ta-legacy.xml";

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    @Test
    public void migrateLegacyTA() throws Exception {
        final Config testConfig = Env.local();
        testConfig.setPersistentStorageDir(tempFolder.getRoot().getAbsolutePath());

        final TA ta = new TA(testConfig);
        TAState taState = ta.migrateTaState(LEGACY_TA_PATH);
        new TAPersistence(testConfig).save(new TAStateSerializer().serialize(taState));

        // do the same manually
        final String legacyXml = new TAPersistence(testConfig).load(LEGACY_TA_PATH);
        final LegacyTA legacyTA = new LegacyTASerializer().deserialize(legacyXml);

        final byte[] encoded = taState.getEncoded();
        final byte[] encodedLegacy = legacyTA.getTrustAnchorKeyStore().getEncoded();

        assertNotNull(taState);
        final Pair<KeyPair, X509ResourceCertificate> decodedLegacy = KeyStore.legacy(testConfig).decode(encodedLegacy);
        final Pair<KeyPair, X509ResourceCertificate> decoded = KeyStore.of(testConfig).decode(encoded);

        assertEquals(decoded.getKey().getPublic(), decodedLegacy.getKey().getPublic());

        // TA last serial should be legacy TA serial + 1:
        assertEquals(legacyTA.lastIssuedCertificateSerial.add(BigInteger.ONE), taState.getLastIssuedCertificateSerial());

        // last crl and manifest number should be set to same value as imported crl / manifest number:
        assertEquals(legacyTA.getLastCrlNumber(), taState.getLastCrlSerial());
        assertEquals(legacyTA.getLastManifestNumber(), taState.getLastMftSerial());
    }

}