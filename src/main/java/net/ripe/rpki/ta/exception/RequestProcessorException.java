package net.ripe.rpki.ta.exception;


public class RequestProcessorException extends RuntimeException {

    private static final long serialVersionUID = 1L;


    public RequestProcessorException(Throwable cause) {
        super(cause);
    }

    public RequestProcessorException(String message) {
        super(message);
    }
}
