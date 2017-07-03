package net.ripe.rpki.ta.serializers;

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

import com.google.common.base.Charsets;
import com.google.common.io.Files;
import net.ripe.rpki.ta.domain.request.SigningRequest;
import net.ripe.rpki.ta.domain.request.TrustAnchorRequest;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class TrustAnchorRequestSerializerTest {

    private static final String TA_P_REQUEST_PATH = "src/test/resources/ta-request.xml";

    @Test
    public void shouldReadTestTaRequest() throws IOException {
        final String requestXml = Files.toString(new File(TA_P_REQUEST_PATH), Charsets.UTF_8);
        final TrustAnchorRequest trustAnchorRequest = new TrustAnchorRequestSerializer().deserialize(requestXml);
        assertNotNull(trustAnchorRequest);

        final SigningRequest taRequest = (SigningRequest) trustAnchorRequest.getTaRequests().get(0);
        assertEquals("6f164750-b184-44ed-aa75-f2eaf4a598c7", taRequest.getRequestId().toString());
        assertEquals("DEFAULT", taRequest.getResourceCertificateRequest().getResourceClassName());
        assertEquals(3, taRequest.getResourceCertificateRequest().getSubjectInformationAccess().length);
        assertEquals(2, trustAnchorRequest.getSiaDescriptors().length);
        assertEquals("1.3.6.1.5.5.7.48.13", trustAnchorRequest.getSiaDescriptors()[0].getMethod().toString());
        assertEquals("http://localhost:7788/notification.xml", trustAnchorRequest.getSiaDescriptors()[0].getLocation().toString());

    }
}
