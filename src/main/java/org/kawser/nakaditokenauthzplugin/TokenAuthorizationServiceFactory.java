package org.kawser.nakaditokenauthzplugin;

import org.zalando.nakadi.plugin.api.SystemProperties;
import org.zalando.nakadi.plugin.api.authz.AuthorizationService;
import org.zalando.nakadi.plugin.api.authz.AuthorizationServiceFactory;


public class TokenAuthorizationServiceFactory implements AuthorizationServiceFactory {

    @Override
    public AuthorizationService init(SystemProperties properties) {
        return new TokenAuthorizationService();
    }
}
