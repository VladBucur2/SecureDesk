package nl.fontys.securedesk.common;

import nl.fontys.securedesk.audit.AuditLog;
import nl.fontys.securedesk.audit.AuditType;
import nl.fontys.securedesk.audit.Outcome;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import tools.jackson.databind.exc.UnrecognizedPropertyException;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Generic error responses (SC-04): the client learns what it may fix and nothing about the
 * internals. Validation failures are audited with field names only, never the values; an unknown
 * field is reported by name, because a request that adds "role" or "status" to a body is what a
 * mass-assignment attempt looks like (T-07).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9_.\\[\\]]{1,40}");

    private final AuditLog audit;

    public GlobalExceptionHandler(AuditLog audit) {
        this.audit = audit;
    }

    @ExceptionHandler(ApiException.class)
    ResponseEntity<ErrorResponse> api(ApiException e) {
        return ResponseEntity.status(e.status()).body(ErrorResponse.of(e.code(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ErrorResponse> invalidBody(MethodArgumentNotValidException e) {
        List<String> fields = e.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getField).map(GlobalExceptionHandler::safe).distinct().sorted().toList();
        return validationFailed(fields, "body");
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    ResponseEntity<ErrorResponse> invalidParameter(HandlerMethodValidationException e) {
        List<String> fields = e.getParameterValidationResults().stream()
                .map(result -> result.getMethodParameter().getParameterName())
                .map(GlobalExceptionHandler::safe).distinct().sorted().toList();
        return validationFailed(fields, "parameter");
    }

    @ExceptionHandler({MethodArgumentTypeMismatchException.class, MissingServletRequestParameterException.class,
            MissingServletRequestPartException.class})
    ResponseEntity<ErrorResponse> badParameter(Exception e) {
        return validationFailed(List.of(), "parameter");
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ErrorResponse> unreadable(HttpMessageNotReadableException e) {
        AuditLog.Entry event = audit.event(AuditType.INPUT_VALIDATION_FAILED).outcome(Outcome.FAILURE);
        if (e.getCause() instanceof UnrecognizedPropertyException unknown) {
            event.detail("reason", "unknown_field").detail("field", safe(unknown.getPropertyName()));
        } else {
            event.detail("reason", "unreadable_body");
        }
        event.write();
        return ResponseEntity.badRequest().body(ErrorResponse.of("malformed_request",
                "The request could not be read."));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    ResponseEntity<ErrorResponse> tooLarge(MaxUploadSizeExceededException e) {
        audit.event(AuditType.UPLOAD_REJECTED).outcome(Outcome.FAILURE).detail("reason", "too_large").write();
        return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
                .body(ErrorResponse.of("too_large", "The file is too large."));
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ErrorResponse> method(HttpRequestMethodNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED)
                .body(ErrorResponse.of("method_not_allowed", "Method not allowed."));
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    ResponseEntity<ErrorResponse> mediaType(HttpMediaTypeNotSupportedException e) {
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE)
                .body(ErrorResponse.of("unsupported_media_type", "Unsupported content type."));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ErrorResponse> noResource(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ErrorResponse.of("not_found", "Not found."));
    }

    /**
     * Anything else is a bug: logged with its stack trace for the administrator, answered with a
     * correlation id only. Security exceptions are handed back to Spring Security, which turns
     * them into 401 or 403 and audits the refusal.
     */
    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponse> unexpected(Exception e) throws Exception {
        if (e instanceof AccessDeniedException || e instanceof AuthenticationException) {
            throw e;
        }
        LOG.error("unhandled exception, correlation_id={}", RequestContext.correlationId(), e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of("internal_error", "Something went wrong. Quote the correlation id if you report it."));
    }

    private ResponseEntity<ErrorResponse> validationFailed(List<String> fields, String where) {
        audit.event(AuditType.INPUT_VALIDATION_FAILED).outcome(Outcome.FAILURE)
                .detail("reason", where).detail("fields", String.join(",", fields)).write();
        return ResponseEntity.badRequest().body(ErrorResponse.withFields("validation_failed",
                "Some fields are missing or not valid.", fields));
    }

    private static String safe(String name) {
        return name != null && SAFE_NAME.matcher(name).matches() ? name : "?";
    }
}
