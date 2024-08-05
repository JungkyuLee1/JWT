package com.example.jwt.controller;

import com.example.jwt.jwt.JWTFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@Controller
@ResponseBody
public class MainController {

//    @Autowired
//    private JWTFilter jwtFilter;

    @GetMapping("/")
    public String mainP(){
        //Session에서 정보가져오기 (token생성 후 일시적 session 생성 상태 )
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        Authentication authentication =SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator= authorities.iterator();
        GrantedAuthority auth= iterator.next();
        String role=auth.getAuthority();




//        return "Main Controller..";
        return "Main Controller.." + username + ":" +role;
    }
}
