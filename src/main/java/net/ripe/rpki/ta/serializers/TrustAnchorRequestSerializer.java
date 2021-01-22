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

import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import net.ripe.rpki.ta.domain.request.ResourceCertificateRequestData;
import net.ripe.rpki.ta.domain.request.RevocationRequest;
import net.ripe.rpki.ta.domain.request.SigningRequest;
import net.ripe.rpki.ta.domain.request.TaRequest;
import net.ripe.rpki.ta.domain.request.TrustAnchorRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.security.auth.x500.X500Principal;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

public class TrustAnchorRequestSerializer extends DomXmlSerializer<TrustAnchorRequest> {

    private static final Base64.Decoder BASE64_DECODER = Base64.getMimeDecoder();
    private static final Base64.Encoder BASE64_ENCODER = Base64.getMimeEncoder();
    public static final String REQUESTS_TRUST_ANCHOR_REQUEST = "requests.TrustAnchorRequest";
    public static final String CREATION_TIMESTAMP = "creationTimestamp";
    public static final String TA_CERTIFICATE_PUBLICATION_URI = "taCertificatePublicationUri";
    public static final String TA_REQUESTS = "taRequests";
    public static final String SIA_DESCRIPTORS = "siaDescriptors";
    public static final String X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR = "X509CertificateInformationAccessDescriptor";
    public static final String METHOD = "method";
    public static final String LOCATION = "location";
    public static final String REQUESTS_REVOCATION_REQUEST = "requests.RevocationRequest";
    public static final String RESOURCE_CLASS_NAME = "resourceClassName";
    public static final String ENCODED_REVOCATION_PUBLIC_KEY = "encodedPublicKey";
    public static final String REQUEST_ID = "requestId";
    public static final String REQUESTS_SIGNING_REQUEST = "requests.SigningRequest";
    public static final String RESOURCE_CERTIFICATE_REQUEST = "resourceCertificateRequest";
    public static final String SUBJECT_DN = "subjectDN";
    public static final String ENCODED_SIGNING_SUBJECT_PUBLIC_KEY = "encodedSubjectPublicKey";
    public static final String SUBJECT_INFORMATION_ACCESS = "subjectInformationAccess";

    public TrustAnchorRequestSerializer() {
        super("");
    }
    
    @Override
    public String serialize(TrustAnchorRequest trustAnchorRequest) {
        if(trustAnchorRequest == null) {
            return "";
        }

        try {
            final Document doc = getDocumentBuilder().newDocument();
            final Element requestsTrustAnchorRequestElement = doc.createElement(REQUESTS_TRUST_ANCHOR_REQUEST);
            doc.appendChild(requestsTrustAnchorRequestElement);

            final Element taCertificatePublicationUriElement = doc.createElement(TA_CERTIFICATE_PUBLICATION_URI);
            final URI taCertificatePublicationUri = trustAnchorRequest.getTaCertificatePublicationUri();
            if(taCertificatePublicationUri != null) {
                taCertificatePublicationUriElement.setTextContent(taCertificatePublicationUri.toString());
                requestsTrustAnchorRequestElement.appendChild(taCertificatePublicationUriElement);
            }

            final Element creationTimestampElement = doc.createElement(CREATION_TIMESTAMP);
            final Long creationTimestamp = trustAnchorRequest.getCreationTimestamp();
            if(creationTimestamp != null) {
                creationTimestampElement.setTextContent(creationTimestamp.toString());
                requestsTrustAnchorRequestElement.appendChild(creationTimestampElement);
            }

            final Element taRequestsElement = doc.createElement(TA_REQUESTS);
            requestsTrustAnchorRequestElement.appendChild(taRequestsElement);
            final List<TaRequest> taRequests = trustAnchorRequest.getTaRequests();
            if(taRequests != null) {
                for (TaRequest taRequest : taRequests) {
                    if (taRequest instanceof SigningRequest) {
                        final Element signingRequestElement = doc.createElement(REQUESTS_SIGNING_REQUEST);
                        taRequestsElement.appendChild(signingRequestElement);

                        serializeSigningRequest(doc, signingRequestElement, (SigningRequest) taRequest);
                    }

                    if (taRequest instanceof RevocationRequest) {
                        final Element revocationRequestElement = doc.createElement(REQUESTS_REVOCATION_REQUEST);
                        taRequestsElement.appendChild(revocationRequestElement);

                        serializeRevocationRequest(doc, revocationRequestElement, (RevocationRequest) taRequest);
                    }
                }
            }

            final Element siaDescriptors = doc.createElement(SIA_DESCRIPTORS);
            requestsTrustAnchorRequestElement.appendChild(siaDescriptors);
            final X509CertificateInformationAccessDescriptor[] descriptors = trustAnchorRequest.getSiaDescriptors();
            if(descriptors != null) {
                for (X509CertificateInformationAccessDescriptor informationAccessDescriptor : descriptors) {
                    serializeSia(doc, siaDescriptors, informationAccessDescriptor);
                }
            }
            return serialize(doc);

        } catch (ParserConfigurationException | TransformerException e) {
            throw new DomXmlSerializerException(e);
        }
    }
    private void serializeRevocationRequest(Document doc, Element revocationRequestElement, RevocationRequest revocationRequest) {
        final Element requestIdElement = doc.createElement(REQUEST_ID);
        revocationRequestElement.appendChild(requestIdElement);
        requestIdElement.setTextContent(revocationRequest.getRequestId().toString());

        final Element resourceClassName = doc.createElement(RESOURCE_CLASS_NAME);
        revocationRequestElement.appendChild(resourceClassName);
        resourceClassName.setTextContent(revocationRequest.getResourceClassName());

        final Element encodedPublicKey = doc.createElement(ENCODED_REVOCATION_PUBLIC_KEY);
        revocationRequestElement.appendChild(encodedPublicKey);
        encodedPublicKey.setTextContent(revocationRequest.getEncodedPublicKey());

    }

    private void serializeSigningRequest(Document doc, Element signingRequestElement, SigningRequest signingRequest) {
        final Element requestIdElement = doc.createElement(REQUEST_ID);
        signingRequestElement.appendChild(requestIdElement);
        requestIdElement.setTextContent(signingRequest.getRequestId().toString());

        final Element resourceCertificateRequestElement = doc.createElement(RESOURCE_CERTIFICATE_REQUEST);
        signingRequestElement.appendChild(resourceCertificateRequestElement);
        final Element resourceClassName = doc.createElement(RESOURCE_CLASS_NAME);
        resourceCertificateRequestElement.appendChild(resourceClassName);
        resourceClassName.setTextContent(signingRequest.getResourceCertificateRequest().getResourceClassName());

        final Element subjectDNElement = doc.createElement(SUBJECT_DN);
        resourceCertificateRequestElement.appendChild(subjectDNElement);
        subjectDNElement.setTextContent(signingRequest.getResourceCertificateRequest().getSubjectDN().getName());

        final Element encodedSubjectPublicKeyElement = doc.createElement(ENCODED_SIGNING_SUBJECT_PUBLIC_KEY);
        resourceCertificateRequestElement.appendChild(encodedSubjectPublicKeyElement);
        encodedSubjectPublicKeyElement.setTextContent(BASE64_ENCODER.encodeToString(signingRequest.getResourceCertificateRequest().getEncodedSubjectPublicKey()));

        final Element subjectInformationAccessElement = doc.createElement(SUBJECT_INFORMATION_ACCESS);
        resourceCertificateRequestElement.appendChild(subjectInformationAccessElement);
        for (X509CertificateInformationAccessDescriptor informationAccessDescriptor: signingRequest.getResourceCertificateRequest().getSubjectInformationAccess()) {
            serializeSia(doc, subjectInformationAccessElement, informationAccessDescriptor);
        }
    }

    private void serializeSia(Document doc, Element subjectInformationAccessElement, X509CertificateInformationAccessDescriptor informationAccessDescriptor) {
        final Element x509CertificateInformationAccessDescriptorElement = doc.createElement(X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR);
        subjectInformationAccessElement.appendChild(x509CertificateInformationAccessDescriptorElement);

        final Element methodElement = doc.createElement(METHOD);
        x509CertificateInformationAccessDescriptorElement.appendChild(methodElement);
        methodElement.setTextContent(informationAccessDescriptor.getMethod().toString());

        final Element locationElement = doc.createElement(LOCATION);
        x509CertificateInformationAccessDescriptorElement.appendChild(locationElement);
        locationElement.setTextContent(informationAccessDescriptor.getLocation().toString());
    }

    @Override
    public TrustAnchorRequest deserialize(final String xml) {
        try (final Reader characterStream = new StringReader(xml)) {
            final Document doc = getDocumentBuilder().parse(new InputSource(characterStream));

            final Element taRequestElement = getElement(doc, REQUESTS_TRUST_ANCHOR_REQUEST)
                    .orElseThrow(() -> new DomXmlSerializerException("requests.TrustAnchorRequest element not found"));

            final Element creationTimestampElement = getSingleChildElement(taRequestElement, CREATION_TIMESTAMP);
            final String creationTimeStampText = getElementTextContent(creationTimestampElement);
            final Long creationTimeStamp;
            try {
                creationTimeStamp = Long.parseLong(creationTimeStampText);
            }catch (NumberFormatException e) {
                throw new DomXmlSerializerException("creationTimestamp content is not a number: " + creationTimeStampText, e);
            }

            final Element taCertificatePublicationUriElement = getSingleChildElement(taRequestElement, TA_CERTIFICATE_PUBLICATION_URI);
            final URI taCertificatePublicationUri = URI.create(getElementTextContent(taCertificatePublicationUriElement));

            final Element requestsListElement = getSingleChildElement(taRequestElement, TA_REQUESTS);
            final List<TaRequest> taRequests = getTaSigningRequests(requestsListElement);
            taRequests.addAll(getTaRevocationRequests(requestsListElement));

            final Element siaDescriptorsElement = getSingleChildElement(taRequestElement, SIA_DESCRIPTORS);
            final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors = getX509CertificateInformationAccessDescriptorArray(siaDescriptorsElement);

            final TrustAnchorRequest trustAnchorRequest = new TrustAnchorRequest(taCertificatePublicationUri, x509CertificateInformationAccessDescriptors, taRequests);

            setField(TrustAnchorRequest.class, trustAnchorRequest, "creationTimestamp", creationTimeStamp);

            return trustAnchorRequest;

        } catch (SAXException | IOException | ParserConfigurationException e) {
            throw new DomXmlSerializerException(e);
        }
    }

    private X509CertificateInformationAccessDescriptor[] getX509CertificateInformationAccessDescriptorArray(Element parent) {
        final List<Element> x509CertificateInformationAccessDescriptorElements = getChildElements(parent, X_509_CERTIFICATE_INFORMATION_ACCESS_DESCRIPTOR);
        final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors = new X509CertificateInformationAccessDescriptor[x509CertificateInformationAccessDescriptorElements.size()];

        int i = 0;
        for (Element x509CertificateInformationAccessElement : x509CertificateInformationAccessDescriptorElements) {
            final Element methodElement = getSingleChildElement(x509CertificateInformationAccessElement, METHOD);
            final String method = getElementTextContent(methodElement);

            final Element locationElement = getSingleChildElement(x509CertificateInformationAccessElement, LOCATION);
            final String location = getElementTextContent(locationElement);

            x509CertificateInformationAccessDescriptors[i] = new X509CertificateInformationAccessDescriptor(new ASN1ObjectIdentifier(method), URI.create(location));
            i++;
        }

        return x509CertificateInformationAccessDescriptors;
    }

    private List<TaRequest> getTaRevocationRequests(Element taRequestElement) {
        List<TaRequest> taRequests = new ArrayList<>();
        final List<Element> revocationRequestElements = getChildElements(taRequestElement, REQUESTS_REVOCATION_REQUEST);
        for(Element revocationRequestElement: revocationRequestElements) {

            final Element resourceClassNameElement = getSingleChildElement(revocationRequestElement, RESOURCE_CLASS_NAME);
            final String resourceClassName = getElementTextContent(resourceClassNameElement);

            final Element encodedSubjectPublicKeyElement = getSingleChildElement(revocationRequestElement, ENCODED_REVOCATION_PUBLIC_KEY);
            final String encodedPublicKey = getElementTextContent(encodedSubjectPublicKeyElement);

            final TaRequest taRequest = new RevocationRequest(resourceClassName, encodedPublicKey);

            final Element requestIdElement = getSingleChildElement(revocationRequestElement, REQUEST_ID);
            final String requestId = getElementTextContent(requestIdElement);
            setField(TaRequest.class, taRequest, "requestId", UUID.fromString(requestId));
            taRequests.add(taRequest);
        }
        return taRequests;
    }

    private List<TaRequest> getTaSigningRequests(Element taRequestElement) {
        List<TaRequest> taRequests = new ArrayList<>();
        final List<Element> signingRequestElements = getChildElements(taRequestElement, REQUESTS_SIGNING_REQUEST);
        for(Element signingRequestElement: signingRequestElements) {
            final Element resourceCertificateRequestElement = getSingleChildElement(signingRequestElement, RESOURCE_CERTIFICATE_REQUEST);

            final Element resourceClassNameElement = getSingleChildElement(resourceCertificateRequestElement, RESOURCE_CLASS_NAME);
            final String resourceClassName = getElementTextContent(resourceClassNameElement);

            final Element subjectDNElement = getSingleChildElement(resourceCertificateRequestElement, SUBJECT_DN);
            final X500Principal subjectDN = new X500Principal(getElementTextContent(subjectDNElement));

            final Element encodedSubjectPublicKeyElement = getSingleChildElement(resourceCertificateRequestElement, ENCODED_SIGNING_SUBJECT_PUBLIC_KEY);
            final byte[] subjectPublicKey = BASE64_DECODER.decode(getElementTextContent(encodedSubjectPublicKeyElement));

            final Element subjectInformationAccessElement = getSingleChildElement(resourceCertificateRequestElement, SUBJECT_INFORMATION_ACCESS);

            final X509CertificateInformationAccessDescriptor[] x509CertificateInformationAccessDescriptors = getX509CertificateInformationAccessDescriptorArray(subjectInformationAccessElement);

            final TaRequest taRequest = new SigningRequest(new ResourceCertificateRequestData(resourceClassName, subjectDN, subjectPublicKey, x509CertificateInformationAccessDescriptors));

            final Element requestIdElement = getSingleChildElement(signingRequestElement, REQUEST_ID);
            final String requestId = getElementTextContent(requestIdElement);
            setField(TaRequest.class, taRequest, "requestId", UUID.fromString(requestId));
            taRequests.add(taRequest);
        }
        return taRequests;
    }

    private String getElementTextContent(Element element) {
        try {
            return element.getTextContent();
        } catch (DOMException e) {
            throw new DomXmlSerializerException("error reading "+element.getLocalName()+" content", e);
        }
    }

    private void setField(Class<?> clazz, Object obj, String fieldName, Object value) {
        try {
            Field privateField = clazz.getDeclaredField(fieldName);
            privateField.setAccessible(true);
            privateField.set(obj, value);
            privateField.setAccessible(false);
        } catch (IllegalAccessException e) {
            throw new DomXmlSerializerException("Unable to inject "+fieldName+": "+value + " into "+obj.getClass().getSimpleName(), e);
        } catch (NoSuchFieldException e) {
            throw new DomXmlSerializerException("Unable to inject "+fieldName+": "+value + " into "+obj.getClass().getSimpleName(), e);
        }
    }
}
