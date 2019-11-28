package net.ripe.rpki.ta.domain.response;


import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang.Validate;

import java.io.Serializable;
import java.util.UUID;

public abstract class TaResponse extends EqualsSupport implements Serializable {

    private static final long serialVersionUID = 1L;

    private UUID requestId;

    protected TaResponse(UUID requestId) {
        Validate.notNull(requestId, "requestId is required");
        this.requestId = requestId;
    }

    public UUID getRequestId() {
        return requestId;
    }
}
