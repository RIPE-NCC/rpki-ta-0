package net.ripe.rpki.ta.serializers;



import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.ta.serializers.legacy.LegacyTA;
import net.ripe.rpki.ta.serializers.legacy.SignedManifest;
import net.ripe.rpki.ta.serializers.legacy.SignedResourceCertificate;

public class LegacyTASerializer extends Serializer<LegacyTA> {

    protected XStreamXmlSerializerBuilder<LegacyTA> configureBuilder(XStreamXmlSerializerBuilder<LegacyTA> builder) {
        builder.withAliasType("TrustAnchor", LegacyTA.class);
        builder.withAliasType("SignedManifest", SignedManifest.class);
        builder.withAliasType("SignedResourceCertificate", SignedResourceCertificate.class);
        return builder;
    }

    protected Class<LegacyTA> clazz() {
        return LegacyTA.class;
    }
}
