package com.example.SpringJWT.jwt;

import com.example.SpringJWT.dto.CustomUserDetails;
import com.example.SpringJWT.entity.RefreshEntity;
import com.example.SpringJWT.repository.RefreshRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final RefreshRepository refreshRepository;

    public LoginFilter(JwtUtil jwtUtil, AuthenticationManager authenticationManager, RefreshRepository refreshRepository) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.refreshRepository = refreshRepository;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        System.out.println(username);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
//        CustomUserDetails principal = (CustomUserDetails) authResult.getPrincipal();
//        String username = principal.getUsername();
//
//        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();
//        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
//        GrantedAuthority auth = iterator.next();
//        System.out.println(auth.getAuthority());
//
//        String role = auth.getAuthority();
//        String token = jwtUtil.createJwt(username, role, 60 * 60 * 10L);
//        response.addHeader("Authorization", "Bearer "+token);

        String username = authResult.getName();

        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String access = jwtUtil.createJwt("access", username, role, 600000L);
        String refresh = jwtUtil.createJwt("refresh", username, role, 86400000L);

        addRefreshEntity(username, refresh, 86400000L);

        response.setHeader("access", access);
        response.addCookie(createCookie("refresh", refresh));
        response.setStatus(HttpStatus.OK.value());
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
    }

    private void addRefreshEntity(String username, String refresh, Long expiredMs){
        Date date = new Date(System.currentTimeMillis() + expiredMs);

        RefreshEntity refreshEntity = new RefreshEntity();
        refreshEntity.setUsername(username);
        refreshEntity.setRefresh(refresh);
        refreshEntity.setExpiration(date.toString());

        refreshRepository.save(refreshEntity);
    }

    private Cookie createCookie(String key, String value){
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(24*60*60);
        // cookie.setSecure(true);
        // cookie.setPath("/");
        cookie.setHttpOnly(true);

        return cookie;
    }
}
