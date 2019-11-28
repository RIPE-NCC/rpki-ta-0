package net.ripe.rpki.ta.domain.response;


import java.util.UUID;

public class ErrorResponse extends TaResponse {

    private static final long serialVersionUID = 1L;

    private String message;

    public ErrorResponse(UUID requestId, String message) {
        super(requestId);
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
