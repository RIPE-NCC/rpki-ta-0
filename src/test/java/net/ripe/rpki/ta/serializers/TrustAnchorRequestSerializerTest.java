package net.ripe.rpki.ta.serializers;


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
