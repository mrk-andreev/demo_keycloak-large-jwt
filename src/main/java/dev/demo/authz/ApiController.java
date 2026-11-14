package dev.demo.authz;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;

@RestController
@RequestMapping("/api")
public class ApiController {
    private final PermissionService permissions;

    ApiController(PermissionService permissions) {
        this.permissions = permissions;
    }

    @GetMapping("/me/permissions")
    public EffectivePermissions effectivePermissions(@AuthenticationPrincipal Jwt jwt,
                                                      @RequestParam(defaultValue = "") String prefix) {
        // Optional prefix avoids returning hundreds of unrelated permissions to the UI.
        List<String> selected = permissions.all(jwt.getSubject()).stream()
                .filter(permission -> permission.startsWith(prefix))
                .sorted().toList();
        return new EffectivePermissions(jwt.getSubject(), selected.size(), selected);
    }

    @PostMapping("/me/permissions/check")
    public Decisions check(@AuthenticationPrincipal Jwt jwt,
                           @Valid @RequestBody CheckRequest request) {
        var effective = permissions.all(jwt.getSubject());
        Map<String, Boolean> decisions = new LinkedHashMap<>();
        request.permissions().forEach(permission -> decisions.put(permission, effective.contains(permission)));
        return new Decisions(decisions);
    }

    @GetMapping("/orders")
    @PreAuthorize("@permissionService.has(authentication.name, 'orders:read')")
    public List<Map<String, Object>> orders() {
        return List.of(Map.of("orderId", 1001, "symbol", "EUR/USD", "status", "NEW"));
    }

    @PostMapping("/orders")
    @PreAuthorize("@permissionService.has(authentication.name, 'orders:create')")
    public ResponseEntity<Map<String, String>> createOrder() {
        return ResponseEntity.ok(Map.of("result", "created"));
    }

    @PostMapping("/orders/cancel")
    @PreAuthorize("@permissionService.has(authentication.name, 'orders:cancel')")
    public ResponseEntity<Map<String, String>> cancelOrder() {
        return ResponseEntity.ok(Map.of("result", "cancelled"));
    }

    public record EffectivePermissions(String subject, int count, List<String> permissions) {}
    public record Decisions(Map<String, Boolean> decisions) {}
    public record CheckRequest(@NotEmpty @Size(max = 100) List<@NotEmpty String> permissions) {}
}
