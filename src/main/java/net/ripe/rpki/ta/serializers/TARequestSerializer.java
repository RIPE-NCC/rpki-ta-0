package net.ripe.rpki.ta.serializers;

import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.domain.request.TaRequest;

public class TARequestSerializer extends Serializer<TaRequest> {

    protected XStreamXmlSerializerBuilder<TaRequest> configureBuilder(XStreamXmlSerializerBuilder<TaRequest> builder) {
        builder.withAliasType("requests.TrustAnchorRequest", TaRequest.class);
        return builder;
    }

    protected Class<TaRequest> clazz() {
        return TaRequest.class;
    }

}
