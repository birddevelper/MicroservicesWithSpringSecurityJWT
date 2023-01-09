package mst.example.authserver.security.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@RequiredArgsConstructor
@Component
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    public static final String HEADER_PREFIX = "Bearer ";

    private final JwtTokenProvider tokenProvider;



    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(HEADER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String token = resolveToken(request);
        if (StringUtils.hasText(token) && this.tokenProvider.validateToken(token)) {

            Authentication authentication = tokenProvider.getAuthentication(token);

            UsernamePasswordAuthenticationToken
                    usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(), null,
                    authentication.getPrincipal() == null ?
                            Arrays.asList() : authentication.getAuthorities()
            );

            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            chain.doFilter(request, response);
            return;
        }

        chain.doFilter(request, response);
    }
}
