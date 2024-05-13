package com.security.amit.security.filter;


import com.security.amit.security.custom.CustomUserDetailService;
import com.security.amit.security.utility.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final CustomUserDetailService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        try {
            Optional.ofNullable(request.getHeader("Authorization"))
                    .filter(authHeader -> StringUtils.startsWith(authHeader, "Bearer "))
                    .map(authHeader -> authHeader.substring(7))
                    .ifPresent(jwt -> {
                        String userEmail = jwtService.extractUserName(jwt);
                        if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
                            UserDetails userDetails = userService.loadUserByUsername(userEmail);
                            if (jwtService.isTokenValid(jwt, userDetails)) {
                                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                        userDetails, null, userDetails.getAuthorities());
                                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                                SecurityContext context = SecurityContextHolder.createEmptyContext();
                                context.setAuthentication(authToken);
                                SecurityContextHolder.setContext(context);
                            }
                        }
                    });
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            logger.error("Error processing JWT: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "SC_UNAUTHORIZED");
//            response.getWriter().write("Unauthorized: JWT token is invalid or expired");
            return; // Important to prevent further filter processing
        }
    }
}
