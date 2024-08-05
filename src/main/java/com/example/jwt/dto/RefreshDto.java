package com.example.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class RefreshDto {
    private Long id;
    private String username;
    private String refreshToken;
    private String expiration;
}
