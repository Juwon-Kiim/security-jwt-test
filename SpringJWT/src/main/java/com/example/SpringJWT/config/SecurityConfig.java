package com.example.SpringJWT.config;

import com.example.SpringJWT.jwt.JwtFilter;
import com.example.SpringJWT.jwt.JwtUtil;
import com.example.SpringJWT.jwt.LoginFilter;
import com.example.SpringJWT.repository.RefreshRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final JwtUtil jwtUtil;

    private final AuthenticationConfiguration authenticationConfiguration;
    private final RefreshRepository refreshRepository;

    public SecurityConfig(JwtUtil jwtUtil, AuthenticationConfiguration authenticationConfiguration, RefreshRepository refreshRepository) {
        this.jwtUtil = jwtUtil;
        this.authenticationConfiguration = authenticationConfiguration;
        this.refreshRepository = refreshRepository;
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .cors(cors -> cors
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration configuration = new CorsConfiguration();

                                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000*"));
                                configuration.setAllowedMethods(Collections.singletonList("*"));
                                configuration.setAllowCredentials(true);
                                configuration.setAllowedHeaders(Collections.singletonList("*"));
                                configuration.setMaxAge(3600L);

                                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                                return configuration;
                            }
                        }))
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasAnyRole("ADMIN")
                        .requestMatchers("/reissue").permitAll()
                        .anyRequest().authenticated());
        http
                .addFilterBefore(new JwtFilter(jwtUtil), LoginFilter.class)
                .addFilterAt(new LoginFilter(jwtUtil, authenticationManager(authenticationConfiguration), refreshRepository), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
