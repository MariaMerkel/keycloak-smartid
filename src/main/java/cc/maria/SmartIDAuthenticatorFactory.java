package cc.maria;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;

public class SmartIDAuthenticatorFactory implements AuthenticatorFactory, ConfigurableAuthenticatorFactory {
    private final SmartIDAuthenticator SINGLETON = new SmartIDAuthenticator();

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static {
        ProviderConfigProperty uiidProperty = new ProviderConfigProperty();
        uiidProperty.setName("rp.uiid");
        uiidProperty.setLabel("Relying Party UIID");
        uiidProperty.setType(ProviderConfigProperty.STRING_TYPE);
        uiidProperty.setHelpText("RPUUID provided by SK");
        configProperties.add(uiidProperty);

        ProviderConfigProperty serviceNameProperty = new ProviderConfigProperty();
        serviceNameProperty.setName("rp.name");
        serviceNameProperty.setLabel("Relying Party Service Name");
        serviceNameProperty.setType(ProviderConfigProperty.STRING_TYPE);
        serviceNameProperty.setHelpText("Service Name to display in Smart-ID app (must be whitelisted by SK)");
        configProperties.add(serviceNameProperty);
    }

    @Override
    public String getDisplayType() {
        return "Smart-ID";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] {AuthenticationExecutionModel.Requirement.REQUIRED};
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "SK Smart-ID authentication";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {}

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return "smartid-authenticator";
    }
}
