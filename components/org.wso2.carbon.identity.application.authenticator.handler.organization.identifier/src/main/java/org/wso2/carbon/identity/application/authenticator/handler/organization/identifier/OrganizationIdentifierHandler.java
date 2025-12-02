/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.handler.organization.identifier;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticationFlowHandler;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationData;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryInput;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationDiscoveryResult;
import org.wso2.carbon.identity.application.authentication.framework.model.OrganizationLoginData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants;
import org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.internal.OrganizationIdentifierHandlerDataHolder;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AMPERSAND_SIGN;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.AUTHENTICATOR_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.EQUAL_SIGN;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.REQUEST_ORG_PAGE_URL_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.handler.organization.identifier.constant.OrganizationIdentifierHandlerConstants.SP_ID_PARAMETER;

/**
 * This class acts as Organization Identifier Handler.
 */
public class OrganizationIdentifierHandler extends AbstractApplicationAuthenticator implements
        AuthenticationFlowHandler {

    private static final Log log = LogFactory.getLog(OrganizationIdentifierHandler.class);

    @Override
    public String getName() {

        return OrganizationIdentifierHandlerConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return OrganizationIdentifierHandlerConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter(OrganizationIdentifierHandlerConstants.CONTEXT_IDENTIFIER);
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        String orgId = request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID);
        String orgHandle = request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_HANDLE);
        String org = request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.ORG_NAME);
        String loginHint = request.getParameter(FrameworkConstants.OrgDiscoveryInputParameters.LOGIN_HINT);
        return StringUtils.isNotEmpty(orgId) || StringUtils.isNotEmpty(orgHandle)
                || StringUtils.isNotEmpty(org) || StringUtils.isNotEmpty(loginHint);
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return super.process(request, response, context);
        }
        if (getParameter(request, context, FrameworkConstants.OrgDiscoveryInputParameters.ORG_ID).isPresent()
                || getParameter(request, context, FrameworkConstants.OrgDiscoveryInputParameters.ORG_HANDLE).isPresent()
                || getParameter(request, context, FrameworkConstants.OrgDiscoveryInputParameters.ORG_NAME).isPresent()
                || getParameter(request, context, FrameworkConstants.OrgDiscoveryInputParameters.LOGIN_HINT).isPresent()
        ) {
            OrganizationDiscoveryResult orgDiscoveryResult = handleOrganizationDiscovery(request, response, context);
            if (orgDiscoveryResult.isSuccessful()) {
                OrganizationLoginData organizationLoginData = new OrganizationLoginData();
                OrganizationData discoveredOrganization = new OrganizationData();
                discoveredOrganization.setId(orgDiscoveryResult.getDiscoveredOrganization().getId());
                discoveredOrganization.setName(orgDiscoveryResult.getDiscoveredOrganization().getName());
                discoveredOrganization.setOrganizationHandle(
                        orgDiscoveryResult.getDiscoveredOrganization().getOrganizationHandle());
                organizationLoginData.setAccessingOrganization(discoveredOrganization);
                organizationLoginData.setSharedApplicationId(orgDiscoveryResult.getSharedApplicationId());
                context.setOrganizationLoginData(organizationLoginData);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        }
        return super.process(request, response, context);
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        redirectToOrgDiscoveryInputCapture(response, context);
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        OrganizationDiscoveryResult orgDiscoveryResult = handleOrganizationDiscovery(request, response, context);
        if (orgDiscoveryResult.isSuccessful()) {
            OrganizationLoginData organizationLoginData = new OrganizationLoginData();
            OrganizationData discoveredOrganization = new OrganizationData();
            discoveredOrganization.setId(orgDiscoveryResult.getDiscoveredOrganization().getId());
            discoveredOrganization.setName(orgDiscoveryResult.getDiscoveredOrganization().getName());
            discoveredOrganization.setOrganizationHandle(
                    orgDiscoveryResult.getDiscoveredOrganization().getOrganizationHandle());
            organizationLoginData.setAccessingOrganization(discoveredOrganization);
            organizationLoginData.setSharedApplicationId(orgDiscoveryResult.getSharedApplicationId());
            context.setOrganizationLoginData(organizationLoginData);
        }
    }

    private OrganizationDiscoveryResult handleOrganizationDiscovery(HttpServletRequest request,
                                                                    HttpServletResponse response,
                                                                    AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            OrganizationDiscoveryInput orgDiscoveryInput = new OrganizationDiscoveryInput.Builder()
                    .orgName(getParameter(request, context,
                            FrameworkConstants.OrgDiscoveryInputParameters.ORG_NAME).orElse(null)).build();


            // FrameworkUtils.getOrganizationDiscoveryInput(request);

            return OrganizationIdentifierHandlerDataHolder.getInstance().getOrganizationDiscoveryHandler()
                    .discoverOrganization(orgDiscoveryInput, context);
        } catch (FrameworkException e) {
            throw new AuthenticationFailedException("Error while discovering organization.", e);
        }
    }

    /**
     * Returns parameter value from the request or runtime parameters.
     *
     * @param request      HTTP servlet request.
     * @param context      Authentication context.
     * @param parameterKey Key of the parameter to retrieve.
     * @return Optional containing the parameter value if present, otherwise empty.
     */
    private Optional<String> getParameter(HttpServletRequest request, AuthenticationContext context,
                                          String parameterKey) {

        Map<String, String> runtimeParams = getRuntimeParams(context);
        if (request.getParameterMap().containsKey(parameterKey)) {
            return Optional.of(request.getParameter(parameterKey));
        } else if (runtimeParams.containsKey(parameterKey)) {
            return Optional.of(runtimeParams.get(parameterKey));
        }
        return Optional.empty();
    }

    @SuppressFBWarnings(value = "UNVALIDATED_REDIRECT", justification = "Redirect params are not based on user inputs.")
    private void redirectToOrgDiscoveryInputCapture(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            StringBuilder queryStringBuilder = new StringBuilder();
            queryStringBuilder.append(SESSION_DATA_KEY).append(EQUAL_SIGN)
                    .append(urlEncode(context.getContextIdentifier()));;
            addQueryParam(queryStringBuilder, AUTHENTICATOR_PARAMETER, getName());
            addQueryParam(queryStringBuilder, SP_ID_PARAMETER, context.getServiceProviderResourceId());

            String url = FrameworkUtils.appendQueryParamsStringToUrl(getOrganizationRequestPageUrl(context),
                        queryStringBuilder.toString());
            response.sendRedirect(url);
        } catch (IOException | URLBuilderException e) {
            throw new AuthenticationFailedException(
                    "Error while redirecting to organization discovery input capture page.", e);
        }
    }

    private void addQueryParam(StringBuilder builder, String query, String param) throws
            UnsupportedEncodingException {

        builder.append(AMPERSAND_SIGN).append(query).append(EQUAL_SIGN).append(urlEncode(param));
    }

    private String urlEncode(String value) throws UnsupportedEncodingException {

        return URLEncoder.encode(value, FrameworkUtils.UTF_8);
    }

    private String getOrganizationRequestPageUrl(AuthenticationContext context) throws URLBuilderException {

        String requestOrgPageUrl = getConfiguration(context, REQUEST_ORG_PAGE_URL_CONFIG);
        if (StringUtils.isBlank(requestOrgPageUrl)) {
            requestOrgPageUrl = REQUEST_ORG_PAGE_URL;
        }
        return ServiceURLBuilder.create().addPath(requestOrgPageUrl).build().getAbsolutePublicURL();
    }

    private String getConfiguration(AuthenticationContext context, String configName) {

        String configValue = null;
        Object propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        String tenantDomain = context.getTenantDomain();
        if ((propertiesFromLocal != null || MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) &&
                super.getAuthenticatorConfig().getParameterMap().containsKey(configName)) {
            configValue = super.getAuthenticatorConfig().getParameterMap().get(configName);
        } else if ((context.getProperty(configName)) != null) {
            configValue = String.valueOf(context.getProperty(configName));
        }
        if (log.isDebugEnabled()) {
            log.debug("Config value for key " + configName + " for tenant " + tenantDomain + " : " + configValue);
        }
        return configValue;
    }
}
