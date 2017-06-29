package net.ripe.rpki.ta.domain.request;

/*
The template:

<requests.TrustAnchorRequest>
  <creationTimestamp>1498649792639</creationTimestamp>
  <taCertificatePublicationUri>rsync://localhost:10873/ta/</taCertificatePublicationUri>
  <taRequests>
    <requests.SigningRequest>
      <requestId>6f164750-b184-44ed-aa75-f2eaf4a598c7</requestId>
      <resourceCertificateRequest>
        <resourceClassName>DEFAULT</resourceClassName>
        <subjectDN>CN=4d6a2ae807f842898b4411b55ae7907180b6b240</subjectDN>
        <subjectInformationAccess>
          <X509CertificateInformationAccessDescriptor>
            <method>1.3.6.1.5.5.7.48.5</method>
            <location>rsync://localhost/online/DEFAULT/96/86d27d-9369-44b3-b3d6-3e8e8ca1bb2c/1/</location>
          </X509CertificateInformationAccessDescriptor>
          <X509CertificateInformationAccessDescriptor>
            <method>1.3.6.1.5.5.7.48.10</method>
            <location>rsync://localhost/online/DEFAULT/96/86d27d-9369-44b3-b3d6-3e8e8ca1bb2c/1/TWoq6Af4QomLRBG1WueQcYC2skA.mft</location>
          </X509CertificateInformationAccessDescriptor>
          <X509CertificateInformationAccessDescriptor>
            <method>1.3.6.1.5.5.7.48.13</method>
            <location>http://localhost:7788/notification.xml</location>
          </X509CertificateInformationAccessDescriptor>
        </subjectInformationAccess>
        <ipResourceSet>0.0.0.0/0, ::</ipResourceSet>
        <encodedSubjectPublicKey>MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhKz+AnIZWNYIEbN+iwjuFuntyg2MfWZ2
A7+ZboLHHYZ2TCIYsf2R/ASFjdGGLCTr/QAJ0GyUideFkRgEsc8jPXPiTGBUx/gaG17nwp55shIn
tNtHCAIR5lXYo0j5sVYNVQOXMEUSP8JSHipH2sd1h0mRkd15lwrKEumn+R0wY53wN2pfa/lo3W+8
0dQm83KD+AGz4QmeiZxXtnLCikE4N8xnqWshmHFvzcP2PDVFxZrj490ydtE9ZoIVTXBR3/AF4GK3
oEP7s5sgEYXzjJMpwWra+E+9Et6NrWE8LX0cXM2FbqkUmTEoIz2VDjjWOJFw9e4nUzwrUuwXp37+
mMswMQIDAQAB</encodedSubjectPublicKey>
      </resourceCertificateRequest>
    </requests.SigningRequest>
  </taRequests>
  <siaDescriptors>
    <X509CertificateInformationAccessDescriptor>
      <method>1.3.6.1.5.5.7.48.13</method>
      <location>http://localhost:7788/notification.xml</location>
    </X509CertificateInformationAccessDescriptor>
    <X509CertificateInformationAccessDescriptor>
      <method>1.3.6.1.5.5.7.48.5</method>
      <location>rsync://localhost/online/</location>
    </X509CertificateInformationAccessDescriptor>
  </siaDescriptors>
</requests.TrustAnchorRequest>

 */
public class TaRequest {

}
