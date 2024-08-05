package com.example.jwt.service;

import com.example.jwt.dto.RefreshDto;

public interface RefreshService {
    public int saveRefresh(RefreshDto refreshDto);
    public Boolean existsRefresh(String refreshToken);
    public int deleteRefreshToken(String refreshToken);
}
