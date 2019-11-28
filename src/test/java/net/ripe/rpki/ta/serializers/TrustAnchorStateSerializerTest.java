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
import com.google.common.io.Files;
import net.ripe.rpki.ta.config.Config;
import net.ripe.rpki.ta.domain.TAState;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.joda.time.DateTime;
import org.joda.time.Period;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class TrustAnchorStateSerializerTest {
    private static final String TA_STATE_PATH = "src/test/resources/acceptance/ta.xml";

    private Document document;

    private TAState state;

    @Before
    public void loadState() throws IOException, SAXException, ParserConfigurationException {
        final String stateXML = Files.toString(new File(TA_STATE_PATH), Charsets.UTF_8);

        final TAStateSerializer trustAnchorStateSerializer = new TAStateSerializer();
        state = trustAnchorStateSerializer.deserialize(stateXML);

        DocumentBuilder builder = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        document = builder.parse(new File(TA_STATE_PATH));
    }

    /**
     * Evaluate an XPath query and return the result.
     * @param query XPath query
     * @return String result of query
     * @throws XPathExpressionException
     */
    private String xpathQuery(String query) throws XPathExpressionException {
        // No lambda's in Java 6 -> utility function
        XPath xpath = XPathFactory.newInstance().newXPath();

        return xpath.evaluate(query, document);
    }

    @Test
    public void shouldMatchSimpleFields() throws XPathExpressionException {
        assertEquals(cleanupBase64(xpathQuery("/TA/encoded")), Base64.toBase64String(state.getEncoded()));

        assertEquals(cleanupBase64(xpathQuery("/TA/crl/encoded")), Base64.toBase64String(state.getCrl().getEncoded()));

        assertEquals(xpathQuery("/TA/keyStorePassphrase"), state.getKeyStorePassphrase());
        assertEquals(xpathQuery("/TA/keyStoreKeyAlias"), state.getKeyStoreKeyAlias());

        assertEquals(new BigInteger(xpathQuery("/TA/lastIssuedCertificateSerial")),
                     state.getLastIssuedCertificateSerial());
        assertEquals(new BigInteger(xpathQuery("/TA/lastCrlSerial")), state.getLastCrlSerial());
        assertEquals(new BigInteger(xpathQuery("/TA/lastMftSerial")), state.getLastMftSerial());
        assertEquals(Long.valueOf(xpathQuery("/TA/lastProcessedRequestTimestamp")),
                     state.getLastProcessedRequestTimestamp());

        assertEquals(new ArrayList(), state.getPreviousTaCertificates());
    }

    @Test
    public void shouldMatchConfigField() throws XPathExpressionException, URISyntaxException {
        Config config = state.getConfig();

        assertEquals(xpathQuery("/TA/config/trustAnchorName"), config.getTrustAnchorName().getName());

        assertEquals(new URI(xpathQuery("/TA/config/taCertificatePublicationUri")),
                     config.getTaCertificatePublicationUri());
        assertEquals(new URI(xpathQuery("/TA/config/taProductsPublicationUri")),
                     config.getTaProductsPublicationUri());
        assertEquals(new URI(xpathQuery("/TA/config/notificationUri")),
                     config.getNotificationUri());

        assertEquals(xpathQuery("/TA/config/keystoreProvider"),
                     config.getKeystoreProvider());
        assertEquals(xpathQuery("/TA/config/keypairGeneratorProvider"),
                                config.getKeypairGeneratorProvider());
        assertEquals(xpathQuery("/TA/config/signatureProvider"),
                     config.getSignatureProvider());
        assertEquals(xpathQuery("/TA/config/keystoreType"),
                     config.getKeystoreType());
        assertEquals(xpathQuery("/TA/config/persistentStorageDir"),
                     config.getPersistentStorageDir());
        assertEquals(Period.parse(xpathQuery("/TA/config/minimumValidityPeriod")),
                     config.getMinimumValidityPeriod());
        assertEquals(Period.parse(xpathQuery("/TA/config/updatePeriod")),
                     config.getUpdatePeriod());
    }

    /**
     * Check the signedProductionCertificates tag and its children.
     */
    @Test
    public void shouldMatchSignedProductionCertificates() throws XPathExpressionException {
        List<SignedResourceCertificate> signedProductionCertificates = state.getSignedProductionCertificates();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/TA/signedProductionCertificates/net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate",
                                                 document,
                                                 XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), signedProductionCertificates.size());

        for (int i=0; i < list.getLength(); i++) {
            SignedResourceCertificate src = signedProductionCertificates.get(i);
            Node cur = list.item(i);

            assertEquals(cleanupBase64(xpath.evaluate("certificateRepositoryObject/encoded", cur)),
                         Base64.toBase64String(src.getResourceCertificate().getEncoded()));

            assertEquals(xpath.evaluate("fileName", cur), src.getFileName());
            // notValidAfter is private -> excluded.
            String revocationTime = xpath.evaluate("revocationTime", cur);

            if (StringUtils.isNotEmpty(revocationTime)) {
                assertEquals(DateTime.parse(revocationTime), src.getRevocationTime());
            } else {
                assertNull(src.getRevocationTime());
            }
        }
    }

    /**
     * Check the signedManifests tag and its children.
     */
    @Test
    public void shouldMatchManifests() throws XPathExpressionException {
        List<SignedManifest> signedManifests = state.getSignedManifests();

        XPath xpath = XPathFactory.newInstance().newXPath();
        NodeList list = (NodeList)xpath.evaluate("/TA/signedManifests/net.ripe.rpki.ta.serializers.legacy.SignedManifest",
                                                 document,
                                                 XPathConstants.NODESET);

        // Check for equal length + identical values.
        assertEquals(list.getLength(), signedManifests.size());

        for (int i=0; i < list.getLength(); i++) {
            SignedManifest smf = signedManifests.get(i);
            Node cur = list.item(i);

            assertEquals(cleanupBase64(xpath.evaluate("certificateRepositoryObject/encoded", cur)),
                         Base64.toBase64String(smf.getManifest().getEncoded()));
        }

    }

    private String cleanupBase64(String s) {
        return s.replaceAll("\\s*", "");
    }
}
