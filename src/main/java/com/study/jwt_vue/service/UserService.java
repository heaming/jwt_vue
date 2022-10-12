package com.study.jwt_vue.service;

import com.study.jwt_vue.entity.User;
import com.study.jwt_vue.repository.UserRepository;
import com.study.jwt_vue.util.SecurityUtil;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public User signup(User user) {
        if(userRepository.findByUsername(user.getUsername()).orElse(null) != null) {
            throw new RuntimeException("Already signed up User");
        }

        User newUser = User.builder()
                .username(user.getUsername())
                .password(passwordEncoder.encode(user.getPassword()))
                .nickname(user.getNickname())
                .email(user.getEmail())
                .role("ROLE_USER")
                .provider(user.getProvider())
                .providerId(user.getProviderId())
                .build();

        return User.from(userRepository.save(newUser));
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities(String username) {
        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUserWithAuthorities() {
        return SecurityUtil.getCurrentUsername().flatMap(userRepository::findByUsername);
    }


}
