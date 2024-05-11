package com.tahauddin.syed.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@RestController
@Slf4j
@RequiredArgsConstructor
public class HomeController {


    @GetMapping("/home")
    public ResponseEntity getHomePage (Principal principal) {
        log.info("Home Page Called ");

        log.info("Principal Object is :: {}", principal.getName());
        return ResponseEntity.ok().build();
    }


    @GetMapping("/home1")
    public ResponseEntity getHomePage1 (@CurrentSecurityContext(expression = "authentication.name") String name) {
        log.info("Home1 Page Called ");
        log.info("Principal Object is :: {}", name);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity getHomePage1 (@RequestBody Map<String, String> request) {

        return ResponseEntity.ok().build();
    }



}
