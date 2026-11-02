package co.il.attendance.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import tools.jackson.databind.json.JsonMapper;

import static co.il.attendance.security.SecurityConstants.AUTHORITIES;
import static co.il.attendance.security.SecurityConstants.TENANT_ID;

@SpringBootTest(classes = TestSecurityApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class BaseSecurityTest {

    protected static final int TENANT = 100;
    protected static final int OTHER_TENANT = 200;
    protected static final String SUBJECT = "1";

    @LocalServerPort
    private int port;

    @Autowired
    private JwtEncoder jwtEncoder;

    private final RestTemplate rest = createRestTemplate();

    private static RestTemplate createRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }
        });
        return restTemplate;
    }

    protected String token(Integer tenantId, String... roles) {
        return token(Instant.now().plusSeconds(60), tenantId, roles);
    }

    protected String token(Instant expiresAt, Integer tenantId, String... roles) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
                .subject(SUBJECT)
                .issuedAt(expiresAt.minusSeconds(3600))
                .expiresAt(expiresAt)
                .claim(AUTHORITIES, List.of(roles));
        if (tenantId != null) {
            claims.claim(TENANT_ID, tenantId);
        }
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), claims.build()))
                .getTokenValue();
    }

    protected ResponseEntity<String> get(String path, String token) {
        return get(path, token, new HttpHeaders());
    }

    protected ResponseEntity<String> get(String path, String token, HttpHeaders headers) {
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return rest.exchange(URI.create("http://localhost:" + port + path), HttpMethod.GET, new HttpEntity<>(headers),
                String.class);
    }

    protected static Map<?, ?> body(ResponseEntity<String> response) {
        return JsonMapper.builder().build().readValue(response.getBody(), Map.class);
    }
}
