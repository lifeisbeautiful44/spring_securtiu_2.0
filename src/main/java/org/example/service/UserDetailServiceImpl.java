package org.example.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    BCryptPasswordEncoder encoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> userDetails = new HashMap<>();
        userDetails.put("srijansil", encoder.encode("password"));
        if (userDetails.containsKey(username)) {
            //returns new USerDetails
            return new User(username, userDetails.get(username), new ArrayList<>());
        }
        throw new UsernameNotFoundException(username + " not found");
    }
}
