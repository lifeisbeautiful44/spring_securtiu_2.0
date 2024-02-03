package org.example.controller;

import org.example.DTO.LoginDTO;
import org.example.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
public class HelloWorldController {

    private AuthenticationManager authenticationManager;

    @Autowired
    public HelloWorldController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping
    public String helloWorld() {
        return "Hello World";
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginDTO loginDTO) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginDTO.getUserName(), loginDTO.getPassword());
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        System.out.println("Everything fine");
        String token = jwtUtil.generate(loginDTO.getUserName());
        return ResponseEntity.ok(token);

    }
}

