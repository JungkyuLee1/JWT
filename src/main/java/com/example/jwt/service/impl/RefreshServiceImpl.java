package com.example.jwt.service.impl;

import com.example.jwt.dto.RefreshDto;
import com.example.jwt.mapper.UserMapper;
import com.example.jwt.service.RefreshService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshServiceImpl implements RefreshService {
    @Autowired
    private UserMapper userMapper;

    @Transactional
    @Override
    public int saveRefresh(RefreshDto refreshDto) {
        return userMapper.saveRefresh(refreshDto);
    }

    @Override
    public Boolean existsRefresh(String refreshToken) {
        return userMapper.existsRefresh(refreshToken);
    }

    @Transactional
    @Override
    public int deleteRefreshToken(String refreshToken) {
        return userMapper.deleteRefreshToken(refreshToken);
    }
}
