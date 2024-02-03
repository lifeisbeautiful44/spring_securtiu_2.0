package org.example.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Service
public class GoogleAuthenticationProvider implements AuthenticationProvider {
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        User googleUser = getUserFromGoogleServer(username, password);
        if (googleUser != null) {
            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(googleUser.getUsername(), googleUser.getPassword(), new ArrayList<>());
            return token;
        }
        throw new BadCredentialsException("Something went wrong");
    }

    private User getUserFromGoogleServer(String username, String password) {

        Map<String,String> googleUser = new HashMap<>();
        googleUser.put("test","test123");
        if(googleUser.containsKey(username) && googleUser.get(username).equals(password))
        {
                 return    new User(username,password,new ArrayList<>());
        }
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
