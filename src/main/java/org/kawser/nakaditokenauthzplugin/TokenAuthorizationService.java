package org.kawser.nakaditokenauthzplugin;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;

import org.zalando.nakadi.plugin.api.authz.AuthorizationAttribute;
import org.zalando.nakadi.plugin.api.authz.AuthorizationService;
import org.zalando.nakadi.plugin.api.authz.Resource;
import org.zalando.nakadi.plugin.api.authz.Subject;
import org.zalando.nakadi.plugin.api.exceptions.AuthorizationInvalidException;
import org.zalando.nakadi.plugin.api.exceptions.OperationOnResourceNotPermittedException;
import org.zalando.nakadi.plugin.api.exceptions.PluginException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;


class TokenAuthorizationSubject implements Subject {
    public TokenAuthorizationSubject() {

    }

    public String getName() {
        return "nakadi-token-authz-plugin";
    }
}

public class TokenAuthorizationService implements AuthorizationService {
//    private static final Logger LOGGER = LoggerFactory.getLogger("NAKADI_TOKEN_AUTHZ_PLUGIN");

    public TokenAuthorizationService() {

    }

    @Override
    public boolean isAuthorized(Operation operation, Resource resource) throws PluginException {
        System.out.println("Username: "+ this.getUsername());
//        LOGGER.info("Username: {}", this.getUsername());
        if (resource == null || resource.getAuthorization() == null) {
            return true;
        }

         Optional<List<AuthorizationAttribute>> authorizationAttributesForOperation = resource.getAttributesForOperation(operation);

         if (authorizationAttributesForOperation.isPresent()) {
             List<AuthorizationAttribute> aaL = authorizationAttributesForOperation.get();
             for(AuthorizationAttribute aa: aaL) {
                 if (aa.getValue().equals(this.getUsername())) {
                     return true;
                 }
             }
         }
         return false;
    }

    @Override
    public void isAuthorizationForResourceValid(Resource resource)
            throws PluginException, AuthorizationInvalidException, OperationOnResourceNotPermittedException {

        System.out.println("Username: "+ this.getUsername());
//        LOGGER.info("Username: {}", this.getUsername());
         if (resource == null || resource.getAuthorization() == null) {
             return;
         }
         Map<String, List<AuthorizationAttribute>> authorization = resource.getAuthorization();
         for (Map.Entry<String, List<AuthorizationAttribute>> entry : authorization.entrySet()) {
             for (AuthorizationAttribute aa : entry.getValue()) {
                 if (!aa.getValue().equals(this.getUsername())) {
                     throw new OperationOnResourceNotPermittedException("Operation is not permitted " + resource.getName());
                 }
             }
         }
    }

    @Override
    public List<Resource> filter(List<Resource> input) throws PluginException {
        return Collections.emptyList();
    }

    @Override
    public Optional<Subject> getSubject() throws PluginException {
        Optional<Subject> opt = Optional.of(new TokenAuthorizationSubject());
        return opt;
    }


    public String getToken() {
        String token;
        token = null;
        OAuth2Authentication authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            token = ((OAuth2AuthenticationDetails) authentication.getDetails()).getTokenValue();
        }
        return token;
    }


    public String getUsername() {
        try {
            return Optional.of(SecurityContextHolder.getContext())
                    .map(SecurityContext::getAuthentication)
                    .map(authentication -> (OAuth2Authentication) authentication)
                    .map(OAuth2Authentication::getUserAuthentication)
                    .map(Authentication::getDetails)
                    .map(details -> (Map) details)
                    .map(details -> details.get("username"))
                    .map(username -> (String) username)
                    .orElse("");
        } catch (final ClassCastException e) {
            return "";
        }
    }

}
