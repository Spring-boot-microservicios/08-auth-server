package com.angelfg.authserver.services;

import com.angelfg.authserver.dtos.TokenDto;
import com.angelfg.authserver.dtos.UserDto;

public interface AuthService {
    TokenDto login(UserDto user);
    TokenDto validateToken(TokenDto token);
}
