package org.kawser.nakaditokenauthzplugin;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.zalando.nakadi.plugin.api.authz.AuthorizationAttribute;
import org.zalando.nakadi.plugin.api.authz.AuthorizationService;
import org.zalando.nakadi.plugin.api.authz.Resource;
import org.zalando.nakadi.plugin.api.authz.Subject;
import org.zalando.nakadi.plugin.api.exceptions.AuthorizationInvalidException;
import org.zalando.nakadi.plugin.api.exceptions.OperationOnResourceNotPermittedException;
import org.zalando.nakadi.plugin.api.exceptions.PluginException;

//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;


class TokenAuthorizationSubject implements Subject {
    public TokenAuthorizationSubject() { }
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
        System.out.println("UID: "+ this.getUID());
//        System.out.println("Token: "+ this.getToken());
//        LOGGER.info("Username: {}", this.getUsername());
        if (resource == null || resource.getAuthorization() == null) {
            return true;
        }

         Optional<List<AuthorizationAttribute>> authorizationAttributesForOperation = resource.getAttributesForOperation(operation);

         if (authorizationAttributesForOperation.isPresent()) {
             List<AuthorizationAttribute> aaL = authorizationAttributesForOperation.get();
             for(AuthorizationAttribute aa: aaL) {
                 if (aa.getValue().equals(this.getUID())) {
                     return true;
                 }
             }
         }
         return false;
    }

    @Override
    public void isAuthorizationForResourceValid(Resource resource)
            throws PluginException, AuthorizationInvalidException, OperationOnResourceNotPermittedException {

        System.out.println("UID: "+ this.getUID());
//        System.out.println("Token: "+ this.getToken());
//        LOGGER.info("Username: {}", this.getUsername());
         if (resource == null || resource.getAuthorization() == null) {
             return;
         }
         Map<String, List<AuthorizationAttribute>> authorization = resource.getAuthorization();
         for (Map.Entry<String, List<AuthorizationAttribute>> entry : authorization.entrySet()) {
             for (AuthorizationAttribute aa : entry.getValue()) {
                 if (!aa.getValue().equals(this.getUID())) {
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
        token = "";
        OAuth2Authentication authentication = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            token = ((OAuth2AuthenticationDetails) authentication.getDetails()).getTokenValue();
        }
        return token;
    }

    public String getFieldFromJsonString(String jsonStr, String fieldName) {
        String regex = "(?<=(\"" + fieldName + "\":\")).*?(?=(\"))";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(jsonStr);
        while (matcher.find()) {
            if (!matcher.group().trim().isEmpty()) {
                return matcher.group().trim();
            }
        }
        return "";
    }

    public String getUID() {
        String token = this.getToken();
        if (!token.isEmpty()) {
            String []tokenArr = token.split("\\.", 3);
            if (tokenArr.length == 3) {
                byte[] decodedURLBytes = Base64.getUrlDecoder().decode(tokenArr[1]);
                String data = new String(decodedURLBytes);
                return this.getFieldFromJsonString(data, "uid");
            }
        }
        return "";
    }


//    public String getUsername() {
//        try {
//            return Optional.of(SecurityContextHolder.getContext())
//                    .map(SecurityContext::getAuthentication)
//                    .map(authentication -> (OAuth2Authentication) authentication)
//                    .map(OAuth2Authentication::getUserAuthentication)
//                    .map(Authentication::getDetails)
//                    .map(details -> (Map) details)
//                    .map(details -> details.get("username"))
//                    .map(username -> (String) username)
//                    .orElse("");
//        } catch (final ClassCastException e) {
//            return "";
//        }
//    }

}
