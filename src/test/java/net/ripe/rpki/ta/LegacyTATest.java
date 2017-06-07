package net.ripe.rpki.ta;

import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.config.Env;
import net.ripe.rpki.ta.persistence.TAPersistence;
import net.ripe.rpki.ta.serializers.LegacyTASerializer;
import net.ripe.rpki.ta.serializers.TAState;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/*-
 * ========================LICENSE_START=================================
 * RIPE NCC Trust Anchor
 * -
 * Copyright (C) 2017 RIPE NCC
 * -
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the RIPE NCC nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * =========================LICENSE_END==================================
 */

@Ignore
public class LegacyTATest {

    private static final String STORAGE_DIR = "src/test/resources/tmp";
    private static final String LEGACY_TA_PATH = "src/test/resources/ta-legacy.xml";

    @Before
    public void setUp() throws Exception {
        cleanTaXml();
    }

    @After
    public void tearDown() throws Exception {
        cleanTaXml();
    }

    @Test
    public void loadLegacyTA() throws Exception {
        final Config testConfig = Env.development();
        testConfig.setPersistentStorageDir(STORAGE_DIR);

        final TA ta = new TA(testConfig);
        TAState taState = ta.migrateTaState(LEGACY_TA_PATH);

        // do the same manually
        final String legacyXml = new TAPersistence(testConfig).load(LEGACY_TA_PATH);
        final LegacyTA legacyTA = new LegacyTASerializer().deserialize(legacyXml);

        final byte[] encoded = taState.getEncoded();
        final byte[] encodedLegacy = legacyTA.getTrustAnchorKeyStore().getEncoded();

        assertNotNull(taState);
        final Pair<KeyPair, X509ResourceCertificate> decodedLegacy = KeyStore.legacy(testConfig).decode(encodedLegacy);
        final Pair<KeyPair, X509ResourceCertificate> decoded = KeyStore.of(testConfig).decode(encoded);

        assertEquals(decoded.getKey().getPublic(), decodedLegacy.getKey().getPublic());
    }


    private void cleanTaXml() {
        new File(STORAGE_DIR + "/ta.xml").delete();
    }

}