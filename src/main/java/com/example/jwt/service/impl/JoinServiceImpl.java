package com.example.jwt.service.impl;

import com.example.jwt.dto.JoinDto;
import com.example.jwt.dto.UserDto;
import com.example.jwt.mapper.UserMapper;
import com.example.jwt.service.JoinService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinServiceImpl implements JoinService {

    @Autowired
    private UserMapper joinMapper;

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    public String joinProcess(JoinDto joinDto) {
        String message = "";

        //User 존재여부 check
        Boolean isExist = joinMapper.existsByUsername(joinDto);
        if (isExist) {
            message = "User exists";
        } else {
            UserDto newUser = new UserDto();

            newUser.setUsername(joinDto.getUsername());
            newUser.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));
            newUser.setRole("ROLE_ADMIN");

            int result = joinMapper.saveUser(newUser);

            if (result > 0) {
                message = "Saved";
            }else{
                message ="Failed";
            }
        }
        return message;
    }
}
