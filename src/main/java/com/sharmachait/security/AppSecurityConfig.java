package com.sharmachait.security;

import com.sharmachait.security.jwt.AuthEntryPointJwt;
import com.sharmachait.security.jwt.AuthTokenFilter;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class AppSecurityConfig{
    @Autowired
    private DataSource dbContext;
    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;
    @Bean
    @Order(SecurityProperties.BASIC_AUTH_ORDER)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth ->
                        auth.requestMatchers("/api/signin").permitAll()
                                .anyRequest().authenticated()
                ).httpBasic(Customizer.withDefaults());
        http.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.exceptionHandling(ex -> ex.authenticationEntryPoint(unauthorizedHandler));
        http.headers(headers -> headers.frameOptions(opt->opt.sameOrigin()));
        http.csrf(csrf->csrf.disable());
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        // the priority of our filter should be before any other auth filter
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    @Transactional
    public CommandLineRunner initUsers(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        return args -> {
            JdbcUserDetailsManager userDetailsManager = (JdbcUserDetailsManager) userDetailsService;

            // Step 1: Create users without roles
            if (!userDetailsManager.userExists("admin")) {
                UserDetails adminUser = User.withUsername("admin")
                        .password(passwordEncoder.encode("adminpassword"))
                        .roles() // No roles yet
                        .build();
                userDetailsManager.createUser(adminUser);
            }

            if (!userDetailsManager.userExists("user")) {
                UserDetails basicUser = User.withUsername("user")
                        .password(passwordEncoder.encode("userpassword"))
                        .roles() // No roles yet
                        .build();
                userDetailsManager.createUser(basicUser);
            }

            // Step 2: Assign roles by updating each user’s authorities directly
            userDetailsManager.updateUser(User.withUsername("admin")
                    .password(passwordEncoder.encode("adminpassword"))
                    .roles("ADMIN")
                    .build());

            userDetailsManager.updateUser(User.withUsername("user")
                    .password(passwordEncoder.encode("userpassword"))
                    .roles("USER")
                    .build());
        };
    }



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthTokenFilter authTokenFilter() {
        return new AuthTokenFilter();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
}
