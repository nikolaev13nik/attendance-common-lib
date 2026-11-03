package co.il.attendance.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static co.il.attendance.security.SecurityConstants.FORBIDDEN;
import static co.il.attendance.security.SecurityConstants.PLATFORM_TENANT_ID;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.ADMINISTRATOR;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.PLATFORM_ADMIN;
import static co.il.attendance.security.SecurityConstants.SecurityRoles.USER;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AccessAnnotationsTest extends BaseSecurityTest {

    private static final String OTHER_SUBJECT = "2";

    private static String userUrl(String idUser) {
        return "/test/tenant/" + TENANT + "/user/" + idUser;
    }

    @Test
    @DisplayName("@AdminOrSelf lets a USER reach the endpoint for their own idUser")
    void adminOrSelfOwnIdTest() {
        ResponseEntity<String> response = get(userUrl(SUBJECT), token(TENANT, USER.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: idUser equals the JWT subject");
    }

    @Test
    @DisplayName("@AdminOrSelf rejects a USER asking for another idUser with 403 Forbidden")
    void adminOrSelfOtherIdForbiddenTest() {
        ResponseEntity<String> response = get(userUrl(OTHER_SUBJECT), token(TENANT, USER.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: a USER may act only on their own idUser");
        assertEquals(FORBIDDEN, body(response).get("message"));
    }

    @Test
    @DisplayName("@AdminOrSelf lets an ADMINISTRATOR reach any idUser of the tenant")
    void adminOrSelfAdministratorTest() {
        ResponseEntity<String> response = get(userUrl(OTHER_SUBJECT), token(TENANT, ADMINISTRATOR.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: ADMINISTRATOR is not limited to self");
    }

    @Test
    @DisplayName("@PlatformAdminOnly lets the platform admin of tenant 0 through")
    void platformAdminOnlyTest() {
        ResponseEntity<String> response = get("/test/platform", token(PLATFORM_TENANT_ID, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.OK, response.getStatusCode(), "Reason: PLATFORM_ADMIN role in tenant 0");
    }

    @Test
    @DisplayName("@PlatformAdminOnly rejects a tenant ADMINISTRATOR with 403 Forbidden")
    void platformAdminOnlyAdministratorForbiddenTest() {
        ResponseEntity<String> response = get("/test/platform", token(TENANT, ADMINISTRATOR.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: a company administrator is not the platform admin");
    }

    @Test
    @DisplayName("@PlatformAdminOnly rejects the PLATFORM_ADMIN role outside tenant 0 with 403 Forbidden")
    void platformAdminOnlyWrongTenantForbiddenTest() {
        ResponseEntity<String> response = get("/test/platform", token(TENANT, PLATFORM_ADMIN.name()));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode(),
                "Reason: the platform admin is the role together with tenant 0");
    }
}
