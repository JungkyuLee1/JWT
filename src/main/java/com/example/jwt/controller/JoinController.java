package com.example.jwt.controller;

import com.example.jwt.dto.JoinDto;
import com.example.jwt.service.JoinService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.function.EntityResponse;

@RestController
@RequestMapping(value = "/")
public class JoinController {

    @Autowired
    private JoinService joinService;

    @PostMapping("/join")
    public ResponseEntity<String> joinProcess(JoinDto joinDto){
        String message="";

        message=joinService.joinProcess(joinDto);

        return ResponseEntity.status(HttpStatus.OK).body(message);
    }
}
