package nl.fontys.securedesk.common;

import org.springframework.http.HttpStatus;

/**
 * An error the client may know about. {@code code} is a stable machine-readable string; the
 * message is written for the user and must never contain internal detail (SC-04).
 */
public class ApiException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final HttpStatus status;
    private final String code;

    public ApiException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }

    public static ApiException badRequest(String code, String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, code, message);
    }

    public static ApiException conflict(String code, String message) {
        return new ApiException(HttpStatus.CONFLICT, code, message);
    }

    /** Also used for "exists but is not yours", so the status code reveals nothing (SC-03). */
    public static ApiException notFound() {
        return new ApiException(HttpStatus.NOT_FOUND, "not_found", "Not found.");
    }
}
