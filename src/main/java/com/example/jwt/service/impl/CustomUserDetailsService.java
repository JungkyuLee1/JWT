package com.example.jwt.service.impl;

import com.example.jwt.dto.CustomUserDetails;
import com.example.jwt.dto.UserDto;
import com.example.jwt.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDto userDto =userMapper.getByUsername(username);

        if(userDto !=null){
            return new CustomUserDetails(userDto);
        }
        return null;
    }
}
