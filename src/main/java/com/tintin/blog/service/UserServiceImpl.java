package com.tintin.blog.service;

import com.tintin.blog.model.Role;
import com.tintin.blog.repository.RoleRepository;
import com.tintin.blog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role  {} to the DB", role.getName());
        return roleRepository.save(role);
    }
}
