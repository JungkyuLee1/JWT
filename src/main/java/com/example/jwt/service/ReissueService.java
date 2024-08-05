package com.example.jwt.service;

import org.springframework.http.ResponseEntity;

public interface ReissueService {
    public ResponseEntity reissueToken(String refreshToken);
}
