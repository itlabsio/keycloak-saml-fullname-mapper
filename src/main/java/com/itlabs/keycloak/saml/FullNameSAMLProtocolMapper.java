package com.itlabs.keycloak.saml;

import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.saml.mappers.AbstractSAMLProtocolMapper;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.SAMLAttributeStatementMapper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class FullNameSAMLProtocolMapper extends AbstractSAMLProtocolMapper
        implements SAMLAttributeStatementMapper {

    public static final String PROVIDER_ID = "saml-full-name-mapper";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        AttributeStatementHelper.setConfigProperties(CONFIG_PROPERTIES);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Full Name Mapper";
    }

    @Override
    public String getDisplayCategory() {
        return AttributeStatementHelper.ATTRIBUTE_STATEMENT_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Maps firstName + lastName to a SAML attribute; falls back to firstName, then username";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public void transformAttributeStatement(AttributeStatementType attributeStatement,
                                            ProtocolMapperModel mappingModel,
                                            KeycloakSession session,
                                            UserSessionModel userSession,
                                            AuthenticatedClientSessionModel clientSession) {

        UserModel user = userSession.getUser();

        String firstName = trimToNull(user.getFirstName());
        String lastName = trimToNull(user.getLastName());
        String username = trimToNull(user.getUsername());

        String value;
        if (firstName != null && lastName != null) {
            value = firstName + " " + lastName;
        } else if (firstName != null) {
            value = firstName;
        } else {
            value = username;
        }

        if (value == null) {
            return;
        }

        AttributeStatementHelper.addAttribute(attributeStatement, mappingModel, value);
    }

    private static String trimToNull(String s) {
        if (s == null) return null;
        String trimmed = s.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}