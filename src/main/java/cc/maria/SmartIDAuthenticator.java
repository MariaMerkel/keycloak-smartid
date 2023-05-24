package cc.maria;

import ee.sk.smartid.*;
import ee.sk.smartid.rest.dao.Interaction;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.io.*;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class SmartIDAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticationHash authenticationHash = AuthenticationHash.generateRandomHash();
        String verificationCode = authenticationHash.calculateVerificationCode();

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(authenticationHash);
            authenticationFlowContext.getAuthenticationSession().setAuthNote("smartid_authentication_hash", Base64.getEncoder().encodeToString(bos.toByteArray()));
            oos.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        };

        authenticationFlowContext.challenge(authenticationFlowContext.form().setAttribute("verification_code", verificationCode).createForm("smartid.ftl"));
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        Map<String, String> config = authenticationFlowContext.getAuthenticatorConfig().getConfig();

        AuthenticationHash authenticationHash;

        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(Base64.getDecoder().decode(authenticationFlowContext.getAuthenticationSession().getAuthNote("smartid_authentication_hash")));
            ObjectInputStream ois = new ObjectInputStream(bis);
            authenticationHash = (AuthenticationHash) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(config.get("rp.uiid"));
        client.setRelyingPartyName(config.get("rp.name"));
        client.setHostUrl("https://rp-api.smart-id.com/v2/");
        client.setTrustedCertificates("-----BEGIN CERTIFICATE-----\nMIIGqTCCBZGgAwIBAgIQAcmsjUmmMvf8JH8Ty+DF2zANBgkqhkiG9w0BAQsFADBP\nMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBE\naWdpQ2VydCBUTFMgUlNBIFNIQTI1NiAyMDIwIENBMTAeFw0yMjA5MTQwMDAwMDBa\nFw0yMzEwMTUyMzU5NTlaMFoxCzAJBgNVBAYTAkVFMRAwDgYDVQQHEwdUYWxsaW5u\nMRswGQYDVQQKExJTSyBJRCBTb2x1dGlvbnMgQVMxHDAaBgNVBAMTE3JwLWFwaS5z\nbWFydC1pZC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCPULrr\nr/JqNZYUc64XVQGWK+NdAyH7JNQVWeQq4Ied+UGiJVX0EdMvQkmi2FLqpUBUchhV\nTIZibrnWJFPn16tul2PaI3WTv5GldlWoT1niArApnVgAHIEyi52ClDrDNcDe0GXR\n5Ew8Ds9yg5r3ic13TZGrATEei1JJuv4A/PgwFIllm2ROjCX+uXdLCE4qdZT4bu9e\nbKIvSlmF9QRcOFcNaykAkjSNo7RI2cTn7Acc8uVxrHpIpgaqupSxM2QTRhe/nUFK\ndaLJOoi9i2cWOWTtvq02jMOeMbYp+tQFrfHrkIIYBAsSLTxkdhvIQiaZQgcYCYCr\nJ05Wf2RSG3OlipSjAgMBAAGjggN0MIIDcDAfBgNVHSMEGDAWgBS3a6LqqKqEjHnq\ntNoPmLLFlXa59DAdBgNVHQ4EFgQUPKNaNumsF6ADFu65t5/GGMmjGowwHgYDVR0R\nBBcwFYITcnAtYXBpLnNtYXJ0LWlkLmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0l\nBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGPBgNVHR8EgYcwgYQwQKA+oDyGOmh0\ndHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRMU1JTQVNIQTI1NjIwMjBD\nQTEtNC5jcmwwQKA+oDyGOmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy\ndFRMU1JTQVNIQTI1NjIwMjBDQTEtNC5jcmwwPgYDVR0gBDcwNTAzBgZngQwBAgIw\nKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMH8GCCsG\nAQUFBwEBBHMwcTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t\nMEkGCCsGAQUFBzAChj1odHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl\ncnRUTFNSU0FTSEEyNTYyMDIwQ0ExLTEuY3J0MAkGA1UdEwQCMAAwggF/BgorBgEE\nAdZ5AgQCBIIBbwSCAWsBaQB2AOg+0No+9QY1MudXKLyJa8kD08vREWvs62nhd31t\nBr1uAAABgzwb0EIAAAQDAEcwRQIhAOJSo5FOcRlXcknJeoC49t8e0zsCeP1h6rua\nyn3Bqs/AAiB3dlLNIjSH6Sr4gXr9rwMdqrRG7lOGNApq+6rvUJUZeQB3ADXPGRu/\nsWxXvw+tTG1Cy7u2JyAmUeo/4SrvqAPDO9ZMAAABgzwb0HcAAAQDAEgwRgIhAPkC\nbPQrvwcPgicv3B1qwPJ6VvhLY0A0jcbv9HU7285YAiEA7cPqSM/0EQsPKV/GHQ2f\nWtfv5XDY8I0zwanL5n5yJiYAdgCzc3cH4YRQ+GOG1gWp3BEJSnktsWcMC4fc8AMO\neTalmgAAAYM8G9CvAAAEAwBHMEUCIBo8+52b+Mb8br+syEJ7y2MBFDDrTjf7q4oN\nagTZLiwTAiEAiXWp56x7C3TrX75SC4CdSmeyQsvl7i2XXfzq2xeWYakwDQYJKoZI\nhvcNAQELBQADggEBAJ8kpUcl7NjH4+qZYmQ33hsS4EoZRT2CJS2xgQ6FCz9BTlRE\nnXyvlX8GoSXljEMPgWHFUyNXytoGITgBaFkbnPklT6OxkW3ZOGg5uEDIsvBKUXuG\nW4irBzLhPBHRAjQcntYnw1QTxuQO2Pm00Yogt8b+P3BBeqnjTYA0nfkgIO6YEMlb\n1qnzZg5MOuNpg1Axj+gcK/W58UIAuI21BVrUQmFqPzioIWHZ+b7WPki5sQSPdkwU\nzEomR37+pxcYg7Kd32YiWeiiHM+OLzfacDGrr/EQqFQVv229z2iQlePyp7Vt4SJm\nvgrfr+MFRe2kz7ge1YBDvr4l3sgDYamFGmVNRL4=\n-----END CERTIFICATE-----\n");

        try {
            SmartIdAuthenticationResponse authenticationResponse = client
                    .createAuthentication()
                    .withSemanticsIdentifierAsString(authenticationFlowContext.getUser().getFirstAttribute("smartid_semantics_identifier"))
                    .withAuthenticationHash(authenticationHash)
                    .withCertificateLevel("QUALIFIED")
                    .withAllowedInteractionsOrder(Collections.singletonList(
                            Interaction.displayTextAndPIN("Log In")
                    ))
                    .authenticate();

            new AuthenticationResponseValidator().validate(authenticationResponse);

            authenticationFlowContext.success();
        } catch (Exception e) {
            authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        String semantics_identifier = userModel.getFirstAttribute("smartid_semantics_identifier");
        if (semantics_identifier == null) return false;
        return semantics_identifier.matches("PNO(EE|LT|LV)-\\d+");
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {}

    @Override
    public void close() {}
}
