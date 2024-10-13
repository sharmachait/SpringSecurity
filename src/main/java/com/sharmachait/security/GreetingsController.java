package com.sharmachait.security;

import com.sharmachait.security.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class GreetingsController {
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authManager;
    @GetMapping("/hi")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> hi(){
        return ResponseEntity.ok("hi");
    }

    @PostMapping("/api/signin")
    public ResponseEntity<?> signin(@RequestBody LoginRequest loginRequest){
        Authentication auth;
        try{
            auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                            loginRequest.getPassword())
            );
        }catch(AuthenticationException e){
            Map<String, Object> map = new HashMap<>();
            map.put("message", e.getMessage());
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }
        SecurityContextHolder.getContext().setAuthentication(auth);
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(role -> role.getAuthority())
                .collect(Collectors.toList());
        return ResponseEntity.ok(new LoginResponse(jwtToken,userDetails.getUsername(),roles));
    }
}
