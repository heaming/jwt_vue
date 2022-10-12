package com.study.jwt_vue.service;

import com.study.jwt_vue.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class PrincipalUserDetailsService implements UserDetailsService {

    private final Logger LOGGER = LoggerFactory.getLogger(PrincipalUserDetailsService.class);

    private final UserRepository userRepository;

    public PrincipalUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .map(user -> new PrincipalUserDetails(user))
//                .map(principalUserDetails -> createPrincipal(username, principalUserDetails))
                .orElseThrow(() -> new UsernameNotFoundException(username + " : 찾을 수 없습니다."));
    }

    private UserDetails createPrincipal(String username, UserDetails user) {
        return new User(username, user.getPassword(), user.getAuthorities());
    }

}
