package com.security.springsecurity6.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        //Bearer Token
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        //posicao "7" devido ao tamanho da string "Bearer "
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt); //extrair o userEmail do token JWT

        //verifica se o email do usuario e nulo ou se nao esta autenticado
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            //verifica se o token e o usuario sao validos
            if(jwtService.isTokenValid(jwt, userDetails)){
               UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                       userDetails,
                       null, //esta nulo porque nao possui credenciais
                       userDetails.getAuthorities()
               );
               authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails((request)));
               SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
