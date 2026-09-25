package net.ripe.rpki.ta.serializers;


import net.ripe.rpki.commons.xml.XStreamXmlSerializer;
import net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilder;
import net.ripe.rpki.commons.xml.XmlSerializer;

import java.util.function.UnaryOperator;

public abstract class Serializer<T> implements XmlSerializer<T> {

    private final XStreamXmlSerializer<T> xStreamXmlSerializer;

    protected Serializer(final Class<T> clazz, final UnaryOperator<XStreamXmlSerializerBuilder<T>> configureBuilder) {
        final XStreamXmlSerializerBuilder<T> builder = XStreamXmlSerializerBuilder.newForgivingXmlSerializerBuilder(clazz);
        this.xStreamXmlSerializer = configureBuilder.apply(builder).build();
    }

    @Override
    public String serialize(final T taState) {
        return this.xStreamXmlSerializer.serialize(taState);
    }

    @Override
    public T deserialize(final String xml) {
        return this.xStreamXmlSerializer.deserialize(xml);
    }
}
