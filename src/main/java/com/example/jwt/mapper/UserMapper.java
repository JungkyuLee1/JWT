package com.example.jwt.mapper;

import com.example.jwt.dto.JoinDto;
import com.example.jwt.dto.RefreshDto;
import com.example.jwt.dto.UserDto;
import org.apache.ibatis.annotations.Mapper;

import java.sql.Ref;

@Mapper
public interface UserMapper {
    public Boolean existsByUsername(JoinDto joinDto);
    public int saveUser(UserDto userDto);
    public UserDto getByUsername(String username);

    public int saveRefresh(RefreshDto refreshDto);
    public Boolean existsRefresh(String refreshToken);
    public int deleteRefreshToken(String refreshToken);
}
