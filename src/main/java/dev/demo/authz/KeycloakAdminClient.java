package dev.demo.authz;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Reads Keycloak's effective CLIENT role mappings for the authenticated user's `sub`.
 * Uses client_credentials with a read-only service account, never an end-user token.
 */
@Component
public class KeycloakAdminClient {
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();
    private final ObjectMapper mapper;
    private final String internalUrl;
    private final String realm;
    private final String catalogClientId;
    private final String serviceClientId;
    private final String serviceClientSecret;
    private volatile ServiceToken serviceToken;
    private volatile String catalogClientUuid;

    public KeycloakAdminClient(ObjectMapper mapper,
                               @Value("${demo.keycloak.admin-base-url}") String internalUrl,
                               @Value("${demo.keycloak.realm}") String realm,
                               @Value("${demo.keycloak.catalog-client-id}") String catalogClientId,
                               @Value("${demo.keycloak.authz-client-id}") String serviceClientId,
                               @Value("${demo.keycloak.authz-client-secret}") String serviceClientSecret) {
        this.mapper = mapper;
        this.internalUrl = internalUrl;
        this.realm = realm;
        this.catalogClientId = catalogClientId;
        this.serviceClientId = serviceClientId;
        this.serviceClientSecret = serviceClientSecret;
    }

    public Set<String> effectivePermissions(String subject) {
        // The subject is taken ONLY from a JWT verified by Spring Security.
        String path = "/admin/realms/" + enc(realm) + "/users/" + enc(subject)
                + "/role-mappings/clients/" + enc(catalogUuid()) + "/composite";
        JsonNode roles = authorizedGet(path);
        if (!roles.isArray()) {
            throw new AuthorizationDependencyException("Unexpected role-mappings response");
        }
        Set<String> result = new HashSet<>();
        for (JsonNode role : roles) {
            String name = role.path("name").asText("");
            // `trader` is the composite parent; only leaf permission roles are exposed.
            if (!name.isBlank() && !name.equals("trader")) {
                result.add(name);
            }
        }
        return Set.copyOf(result);
    }

    private String catalogUuid() {
        String result = catalogClientUuid;
        if (result != null) return result;
        synchronized (this) {
            if (catalogClientUuid == null) {
                JsonNode clients = authorizedGet("/admin/realms/" + enc(realm)
                        + "/clients?clientId=" + enc(catalogClientId));
                if (!clients.isArray() || clients.isEmpty()) {
                    throw new AuthorizationDependencyException("Permission catalog client not found");
                }
                catalogClientUuid = clients.get(0).path("id").asText();
            }
            return catalogClientUuid;
        }
    }

    private JsonNode authorizedGet(String path) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(internalUrl + path))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + adminAccessToken())
                    .GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new AuthorizationDependencyException("Keycloak Admin API returned HTTP " + response.statusCode());
            }
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new AuthorizationDependencyException("Keycloak Admin API communication failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthorizationDependencyException("Keycloak Admin API call interrupted", e);
        }
    }

    private String adminAccessToken() throws IOException, InterruptedException {
        ServiceToken cached = serviceToken;
        if (cached != null && System.currentTimeMillis() < cached.expiresAtMillis()) {
            return cached.value();
        }
        synchronized (this) {
            cached = serviceToken;
            if (cached != null && System.currentTimeMillis() < cached.expiresAtMillis()) {
                return cached.value();
            }
            String form = "grant_type=client_credentials&client_id=" + enc(serviceClientId)
                    + "&client_secret=" + enc(serviceClientSecret);
            HttpRequest request = HttpRequest.newBuilder(URI.create(internalUrl + "/realms/"
                            + enc(realm) + "/protocol/openid-connect/token"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form)).build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new AuthorizationDependencyException("Service account token request failed: HTTP " + response.statusCode());
            }
            JsonNode token = mapper.readTree(response.body());
            long lifetime = token.path("expires_in").asLong(60);
            serviceToken = new ServiceToken(token.path("access_token").asText(),
                    System.currentTimeMillis() + Math.max(1, lifetime - 30) * 1000);
            return serviceToken.value();
        }
    }

    private static String enc(String input) {
        return URLEncoder.encode(input, StandardCharsets.UTF_8);
    }

    private record ServiceToken(String value, long expiresAtMillis) { }
}
