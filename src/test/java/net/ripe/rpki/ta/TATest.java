package net.ripe.rpki.ta;

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
        final String xml = TA.serialize(new TA(Env.local()).initialiseTaState());
        assertTrue(xml.contains("<taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>"));
        assertTrue(xml.contains("<taProductsPublicationUri>rsync://localhost:10873/repository/</taProductsPublicationUri>"));
        assertTrue(xml.contains("<keystoreProvider>SUN</keystoreProvider>"));
        assertTrue(xml.contains("<keypairGeneratorProvider>SunRsaSign</keypairGeneratorProvider>"));
        assertTrue(xml.contains("<signatureProvider>SunRsaSign</signatureProvider>"));
        assertTrue(xml.contains("<keystoreType>JKS</keystoreType>"));
        final String home = System.getenv("HOME");
        assertTrue(xml.contains("<persistentStorageDir>" + home + "/export/bad/certification/ta/data</persistentStorageDir>"));
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
