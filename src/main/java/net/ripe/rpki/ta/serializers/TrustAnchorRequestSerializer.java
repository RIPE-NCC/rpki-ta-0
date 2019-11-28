package net.ripe.rpki.ta.serializers;


import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.domain.request.TrustAnchorRequest;

public class TrustAnchorRequestSerializer extends Serializer<TrustAnchorRequest> {

    protected XStreamXmlSerializerBuilder<TrustAnchorRequest> configureBuilder(XStreamXmlSerializerBuilder<TrustAnchorRequest> builder) {
        builder.withAliasPackage("requests", TrustAnchorRequest.class.getPackage().getName());
        return builder;
    }

    protected Class<TrustAnchorRequest> clazz() {
        return TrustAnchorRequest.class;
    }

}
