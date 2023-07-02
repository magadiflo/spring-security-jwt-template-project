package com.magadiflo.jwt.template.project.app.security.filter;

import com.magadiflo.jwt.template.project.app.security.utility.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger LOG = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!this.jwtTokenProvider.isBearerToken(request)) {
            LOG.error("No procesó la solicitud de autenticación porque no pudo encontrar el formato bearer token en " +
                    "el encabezado de autorización");
            filterChain.doFilter(request, response);
            return;
        }

        String token = this.jwtTokenProvider.tokenFromRequest(request);

        if (!this.jwtTokenProvider.isAccessTokenValid(token)) {
            LOG.error("El access token proporcionado no pasó la validación de la librería auth0/java-jwt");
            filterChain.doFilter(request, response);
            return;
        }

        String username = this.jwtTokenProvider.getSubjectFromAccessToken(token);
        List<GrantedAuthority> authorities = this.jwtTokenProvider.getAuthoritiesFromAccessToken(token);

        var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
