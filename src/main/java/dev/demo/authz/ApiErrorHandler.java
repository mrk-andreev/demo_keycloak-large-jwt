package dev.demo.authz;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiErrorHandler {
    @ExceptionHandler(AuthorizationDependencyException.class)
    ResponseEntity<Map<String, String>> unavailable(AuthorizationDependencyException exception) {
        // Fail closed if Keycloak is unavailable on an uncached request.
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", "authorization_unavailable", "detail", exception.getMessage()));
    }
}
