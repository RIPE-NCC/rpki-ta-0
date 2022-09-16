package net.ripe.rpki.ta.serializers;


import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.commons.xml.XmlSerializer;

public abstract class Serializer<T> implements XmlSerializer<T> {

    private final XStreamXmlSerializer<T> xStreamXmlSerializer;

    protected Serializer() {
        final XStreamXmlSerializerBuilder<T> builder = XStreamXmlSerializerBuilder.newForgivingXmlSerializerBuilder(clazz());
        this.xStreamXmlSerializer = configureBuilder(builder).build();
    }

    protected abstract XStreamXmlSerializerBuilder<T> configureBuilder(XStreamXmlSerializerBuilder<T> builder);

    protected abstract Class<T> clazz();

    @Override
    public String serialize(final T taState) {
        return this.xStreamXmlSerializer.serialize(taState);
    }

    @Override
    public T deserialize(final String xml) {
        return this.xStreamXmlSerializer.deserialize(xml);
    }
}
