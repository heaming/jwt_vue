package com.study.jwt_vue.service;

import com.study.jwt_vue.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

public class PrincipalUserDetails implements UserDetails {

    private final Logger LOGGER = LoggerFactory.getLogger(PrincipalUserDetails.class);

    private User user;
    private Map<String, Object> attributes;
    private Collection<? extends GrantedAuthority> authorities;

    public PrincipalUserDetails(User user) {
        this.user = user;
    }

    public PrincipalUserDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        Collection<GrantedAuthority> collect = new ArrayList<>();
        this.authorities = this.user.getRoleList().stream().map(
                role -> new SimpleGrantedAuthority(role)
        ).collect(Collectors.toList());

//        user.getRoleList().forEach(
//                role -> {
//                    collect.add(() -> role);
//                });

        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public String getName() {
        return user.getUsername();
    }

//    public UserDetails getPrincipal() {
//        return User
//    }
}
