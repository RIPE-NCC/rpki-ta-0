package net.ripe.rpki.ta.domain.request;


import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.util.EqualsSupport;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.security.PublicKey;

public class ResourceCertificateRequestData extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final X500Principal subjectDN;
    private final X509CertificateInformationAccessDescriptor[] subjectInformationAccess;
    private final byte[] encodedSubjectPublicKey;


    public ResourceCertificateRequestData(String resourceClassName, X500Principal subjectDN, PublicKey subjectPublicKey,
                                          X509CertificateInformationAccessDescriptor[] subjectInformationAccess, IpResourceSet ipResourceSet) {
        this(resourceClassName, subjectDN, subjectPublicKey.getEncoded(), subjectInformationAccess, ipResourceSet);
    }

    public ResourceCertificateRequestData(String resourceClassName, X500Principal subjectDN, byte[] encodedSubjectPublicKey, //NOPMD - ArrayIsStoredDirectly
                                          X509CertificateInformationAccessDescriptor[] subjectInformationAccess, IpResourceSet ipResourceSet) { //NOPMD - ArrayIsStoredDirectly
        this.resourceClassName = resourceClassName;
        this.subjectDN = subjectDN;
        this.encodedSubjectPublicKey = encodedSubjectPublicKey;
        this.subjectInformationAccess = subjectInformationAccess;
    }

    public String getResourceClassName() {
        return resourceClassName;
    }

    public X500Principal getSubjectDN() {
        return subjectDN;
    }

    public byte[] getEncodedSubjectPublicKey() {
        return encodedSubjectPublicKey;
    }

    public X509CertificateInformationAccessDescriptor[] getSubjectInformationAccess() {
        return subjectInformationAccess;
    }
}
