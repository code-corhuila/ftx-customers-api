package com.futbolix.customers.adapter.in.web;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.UnrecognizedPropertyException;
import com.futbolix.customers.application.InvalidCredentialsException;
import com.futbolix.customers.application.InvalidRefreshTokenException;
import com.futbolix.customers.application.TooManyLoginAttemptsException;
import java.util.List;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Maps every failure to the ErrorResponse of _shared.yaml. Never leaks internals (A05/A09) and
 * never echoes a submitted value: a password typed in the email field must not come back.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ErrorResponse> invalidBody(MethodArgumentNotValidException e) {
        List<ErrorResponse.Detail> details = e.getBindingResult().getFieldErrors().stream()
                .map(f -> new ErrorResponse.Detail(f.getField(), message(f.getCode())))
                .distinct()
                .toList();
        return validation(details);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<ErrorResponse> unreadableBody(HttpMessageNotReadableException e) {
        Throwable cause = e.getCause();
        if (cause instanceof UnrecognizedPropertyException unknown) {
            return validation(List.of(new ErrorResponse.Detail(path(unknown), "Unknown field")));
        }
        if (cause instanceof InvalidFormatException invalid) {
            return validation(List.of(new ErrorResponse.Detail(path(invalid), "Invalid value")));
        }
        return validation(List.of(new ErrorResponse.Detail(null, "The body must be a JSON object")));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    ResponseEntity<ErrorResponse> invalidCredentials() {
        return error(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Invalid email or password");
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    ResponseEntity<ErrorResponse> invalidRefreshToken() {
        return error(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", "The refresh token is invalid or expired");
    }

    @ExceptionHandler(AuthController.AuthenticationRequiredException.class)
    ResponseEntity<ErrorResponse> unauthenticated() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .body(body("UNAUTHORIZED", "Authentication is required", List.of()));
    }

    @ExceptionHandler(TooManyLoginAttemptsException.class)
    ResponseEntity<ErrorResponse> tooManyRequests(TooManyLoginAttemptsException e) {
        long seconds = Math.max(1, (e.retryAfter().toMillis() + 999) / 1000);
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(seconds))
                .body(body("TOO_MANY_REQUESTS", "Too many requests, try again later", List.of()));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    ResponseEntity<ErrorResponse> notFound() {
        return error(HttpStatus.NOT_FOUND, "NOT_FOUND", "The requested resource was not found");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    ResponseEntity<ErrorResponse> methodNotAllowed() {
        return error(HttpStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "The method is not allowed on this resource");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    ResponseEntity<ErrorResponse> unsupportedMediaType() {
        return error(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE", "Send the body as application/json");
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ErrorResponse> unexpected(Exception e) {
        log.error("Unexpected error", e);
        return error(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected internal server error occurred");
    }

    private static String message(String constraint) {
        if (constraint == null) {
            return "Invalid value";
        }
        return switch (constraint) {
            case "NotBlank", "NotNull" -> "Required";
            case "Email" -> "Must be a valid email address";
            case "Size" -> "Invalid length";
            default -> "Invalid value";
        };
    }

    private static ResponseEntity<ErrorResponse> validation(List<ErrorResponse.Detail> details) {
        return ResponseEntity.badRequest().body(body("VALIDATION_ERROR", "Invalid request data", details));
    }

    private static ResponseEntity<ErrorResponse> error(HttpStatus status, String code, String message) {
        return ResponseEntity.status(status).body(body(code, message, List.of()));
    }

    private static ErrorResponse body(String code, String message, List<ErrorResponse.Detail> details) {
        return new ErrorResponse(code, message, details, MDC.get(CorrelationIdFilter.MDC_KEY));
    }

    private static String path(JsonMappingException e) {
        return e.getPath().stream()
                .map(ref -> ref.getFieldName() != null ? ref.getFieldName() : "[" + ref.getIndex() + "]")
                .collect(Collectors.joining("."));
    }
}
