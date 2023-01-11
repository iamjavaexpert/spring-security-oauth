package com.baeldung.resource.config;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter(urlPatterns = "/*")
@Component
public class SecurityFilter implements Filter {
    public static final String PREFERRED_USERNAME= "preferred_username";

    public static final String DOMAIN= "@test.com";

    public static final String DOMAIN_NOT_VALID= "Domain is not valid";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        JwtAuthenticationToken principal = (JwtAuthenticationToken) ((HttpServletRequest) request).getUserPrincipal();
        if(principal!=null) {
            String username = principal.getToken().getClaimAsString(PREFERRED_USERNAME);
            // if domain end with test.com then it will frorward request to handler otherwise it will throw unauthorised exception
            if (username != null && username.endsWith(DOMAIN)) {
                chain.doFilter(request, response);
            } else {
                ((HttpServletResponse) response).sendError(HttpServletResponse.SC_UNAUTHORIZED, DOMAIN_NOT_VALID);
            }
        }
    }
}