package eu.sell.alphagateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Objects;

public class AuthFilter extends BasicAuthenticationFilter {

    private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

    private final Environment env;
    private final AuthenticationManager authManager;

    public AuthFilter(AuthenticationManager authenticationManager, Environment environment) {
        super(authenticationManager);
        this.env = environment;
        this.authManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String authHeader = request.getHeader(env.getProperty("auth.token.header.name"));

        if (authHeader == null || !authHeader.startsWith(Objects.requireNonNull(env.getProperty("auth.token.header.prefix")))) {
            chain.doFilter(request, response);
            return;
        }
        UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        chain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
        String header = req.getHeader(env.getProperty("auth.token.header.name"));
        if (header == null) {
            return null;
        }

        String token = header.replace(Objects.requireNonNull(env.getProperty("authorization.token.header.prefix")), "");
        Claims userClaims = Jwts.parser()
                .setSigningKey(env.getProperty("auth.secret_key"))
                .parseClaimsJws(token)
                .getBody();

        // TODO: Probably have to query roles for user
        if (userClaims.getSubject() == null) {
            return null;
        }
        log.info(userClaims.values().toString());
        return new UsernamePasswordAuthenticationToken(userClaims.getSubject(), null, new ArrayList<>());
    }
}
