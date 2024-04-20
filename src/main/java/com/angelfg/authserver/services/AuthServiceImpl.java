package com.angelfg.authserver.services;

import com.angelfg.authserver.dtos.TokenDto;
import com.angelfg.authserver.dtos.UserDto;
import com.angelfg.authserver.entities.UserEntity;
import com.angelfg.authserver.helpers.JwtHelper;
import com.angelfg.authserver.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Transactional
@AllArgsConstructor
@Service
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtHelper jwtHelper;

    private static final String USER_EXCEPTION_MESSAGE = "Error to auth user";

    @Override
    public TokenDto login(UserDto user) {
        final UserEntity userFromDB = this.userRepository.findByUsername(user.getUsername())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MESSAGE));

        this.validPassword(user, userFromDB);

        return TokenDto.builder()
            .accessToken(this.jwtHelper.createToken(userFromDB.getUsername()))
            .build();
    }

    @Override
    public TokenDto validateToken(TokenDto tokenDto) {

        if (this.jwtHelper.validateToken(tokenDto.getAccessToken())) {
            return TokenDto.builder()
                .accessToken(tokenDto.getAccessToken())
                .build();
        }

        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MESSAGE);
    }

    private void validPassword(UserDto userDto, UserEntity userEntity) {
        if (!this.passwordEncoder.matches(userDto.getPassword(), userEntity.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, USER_EXCEPTION_MESSAGE);
        }
    }

}
