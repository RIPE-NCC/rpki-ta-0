package net.ripe.rpki.ta.serializers;

import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.domain.response.ErrorResponse;
import net.ripe.rpki.ta.domain.response.RevocationResponse;
import net.ripe.rpki.ta.domain.response.SigningResponse;
import net.ripe.rpki.ta.domain.response.TaResponse;


public class TAResponseSerializer extends Serializer<TaResponse> {

    protected XStreamXmlSerializerBuilder<TaResponse> configureBuilder(XStreamXmlSerializerBuilder<TaResponse> builder) {
        builder.withAliasType("TrustAnchorResponse", TaResponse.class);
        builder.withAliasType("SigningResponse", SigningResponse.class);
        builder.withAliasType("RevocationResponse", RevocationResponse.class);
        builder.withAliasType("ErrorResponse", ErrorResponse.class);

        builder.withAliasType("X509ResourceCertificate", X509ResourceCertificate.class);
        builder.withAliasType("CRL", X509Crl.class);
        builder.withAliasType("Manifest", ManifestCms.class);
        builder.withAliasType("Roa", RoaCms.class);
        builder.withAliasType("RoaPrefix", RoaPrefix.class);
        return builder;
    }

    protected Class<TaResponse> clazz() {
        return TaResponse.class;
    }


}
