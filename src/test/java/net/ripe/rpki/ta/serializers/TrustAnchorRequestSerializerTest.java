/**
 * Copyright © 2017, RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the <organization> nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.ta.serializers;


import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.domain.request.ResourceCertificateRequestData;
import net.ripe.rpki.ta.domain.request.SigningRequest;
import net.ripe.rpki.ta.domain.request.TaRequest;
import net.ripe.rpki.ta.domain.request.TrustAnchorRequest;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.UUID;

import static net.ripe.rpki.ta.serializers.Utils.cleanupBase64;
import static org.junit.Assert.*;

public class TrustAnchorRequestSerializerTest {

    private static final String TA_REQUEST_PATH = "src/test/resources/ta-request.xml";

    private Document document;
    private XPath xpath = XPathFactory.newInstance().newXPath();

    private TrustAnchorRequest request;

    @Before
    public void loadState() throws IOException, SAXException, ParserConfigurationException {
        final String stateXML = Files.toString(new File(TA_REQUEST_PATH), Charsets.UTF_8);

        final TrustAnchorRequestSerializer trustAnchorRequestSerializer = new TrustAnchorRequestSerializer();
        request = trustAnchorRequestSerializer.deserialize(stateXML);

        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        document = builder.parse(new File(TA_REQUEST_PATH));
    }

    /**
     * Evaluate an XPath query and return the result.
     * @param query XPath query
     * @return String result of query
     * @throws XPathExpressionException
     */
    private String xpathQuery(String query) throws XPathExpressionException {
        // No lambda's in Java 6 -> utility function
        return xpath.evaluate(query, document);
    }

    @Test
    public void shouldReadBasicFields() throws IOException, XPathExpressionException {
        assertEquals(Long.valueOf(xpathQuery("/requests.TrustAnchorRequest/creationTimestamp")), request.getCreationTimestamp());
        assertEquals(URI.create(xpathQuery("/requests.TrustAnchorRequest/taCertificatePublicationUri")), request.getTaCertificatePublicationUri());
    }

    /**
     * Validate a X509CertificateInformationAccessDescriptor
     */
    private void validateX509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor ciad, Node node) throws XPathExpressionException {
        assertEquals(xpath.evaluate("method", node), ciad.getMethod().toString());
        assertEquals(URI.create(xpath.evaluate("location", node)), ciad.getLocation());
    }

    /**
     *
     */
    private void shouldReadSigningRequest(SigningRequest sr, Node cur) throws XPathExpressionException {
        assertEquals(UUID.fromString(xpath.evaluate("requestId", cur)), sr.getRequestId());

        ResourceCertificateRequestData rcrd = sr.getResourceCertificateRequest();

        assertEquals(cleanupBase64(xpath.evaluate("resourceCertificateRequest/encodedSubjectPublicKey", cur)),
                     Base64.toBase64String(rcrd.getEncodedSubjectPublicKey()));

        assertEquals(xpath.evaluate("resourceCertificateRequest/resourceClassName", cur), rcrd.getResourceClassName());
        assertEquals(xpath.evaluate("resourceCertificateRequest/subjectDN", cur), rcrd.getSubjectDN().getName());

        // Loop over the subjectInformationAccess values
        X509CertificateInformationAccessDescriptor[] sia = rcrd.getSubjectInformationAccess();
        NodeList siaList = (NodeList)xpath.evaluate("resourceCertificateRequest/subjectInformationAccess/X509CertificateInformationAccessDescriptor",
                cur,
                XPathConstants.NODESET);

        assertEquals(siaList.getLength(), sia.length);
        for (int j=0; j < siaList.getLength(); j++) {
            validateX509CertificateInformationAccessDescriptor(sia[j], siaList.item(j));
        }
    }

    @Test
    public void shouldReadTARequests() throws XPathExpressionException {
        List<TaRequest> signingRequests = request.getTaRequests();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/requests.TrustAnchorRequest/taRequests/requests.SigningRequest",
                document,
                XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), signingRequests.size());

        for (int i=0; i < list.getLength(); i++) {
            // implicit: instanceof otherwise: ClassCastException.
            shouldReadSigningRequest((SigningRequest)signingRequests.get(i), list.item(i));
        }
    }

    @Test
    public void shouldReadSiaDescriptors() throws XPathExpressionException {
        X509CertificateInformationAccessDescriptor[] siaDescriptors = request.getSiaDescriptors();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/requests.TrustAnchorRequest/siaDescriptors/X509CertificateInformationAccessDescriptor",
                document,
                XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), siaDescriptors.length);

        for (int i=0; i < list.getLength(); i++) {
            validateX509CertificateInformationAccessDescriptor(siaDescriptors[i], list.item(i));
        }
    }
}
