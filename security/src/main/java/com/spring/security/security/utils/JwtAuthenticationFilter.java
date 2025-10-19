package com.spring.security.security.utils;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

//Kjo klasë është një filter që vepron për çdo request që vjen në aplikacion dhe:
//Kontrollon nëse request-i ka një JWT token.
//Verifikon tokenin (është i saktë? a ka skaduar?)
//Nëse është valid, vendos përdoruesin në Spring Security → që të lejohet të
// hyjë në endpoint-et e mbrojtura.
//3
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter { //Bën që kjo klasë të jetë
    // një filter që ekzekutohet një herë për çdo kërkesë HTTP.


    //klasa që krijon dhe verifikon JWT token-at.
    @Autowired
    private JwtUtil jwtUtil;

    // ngarkon përdoruesin nga databaza sipas email-it (username-it).
    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        String jwt = null;
        String userEmail = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            jwt = authHeader.substring(7); //heq "Bearer " nga fillimi
            userEmail = jwtUtil.extractUsername(jwt);
        }

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            if (jwtUtil.isTokenValid(jwt, userDetails.getUsername())) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                //Lejon Spring-in të dijë që ky është një përdorues i loguar
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        //	Lejon kërkesën të vazhdojë nëse gjithçka është në rregull
        filterChain.doFilter(request, response);
    }
}