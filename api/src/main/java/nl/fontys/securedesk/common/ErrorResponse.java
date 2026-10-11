package nl.fontys.securedesk.common;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

/**
 * The only shape an error takes. No exception class, no stack trace, no SQL: the correlation id
 * lets an administrator find the details in the log instead.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(String error, String message, List<String> fields, String correlationId) {

    public static ErrorResponse of(String error, String message) {
        return new ErrorResponse(error, message, null, RequestContext.correlationId());
    }

    public static ErrorResponse withFields(String error, String message, List<String> fields) {
        return new ErrorResponse(error, message, fields, RequestContext.correlationId());
    }
}
