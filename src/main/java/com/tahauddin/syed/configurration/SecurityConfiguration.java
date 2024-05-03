package com.tahauddin.syed.configurration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@Slf4j
public class SecurityConfiguration {


    @Bean
    public PasswordEncoder passwordEncoder () {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails syed = User
                .withUsername("Josh")
                .passwordEncoder(encoder -> passwordEncoder().encode("Long"))
                .build();

        UserDetails mohd = User
                .withUsername("John")
                .passwordEncoder(encoder -> passwordEncoder().encode("Thompson"))
                .build();

        return new InMemoryUserDetailsManager(syed, mohd);
    }


}
