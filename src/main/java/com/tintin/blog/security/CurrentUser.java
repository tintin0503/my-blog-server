package com.tintin.blog.security;


import org.springframework.security.core.annotation.AuthenticationPrincipal;

import java.lang.annotation.*;

@Target({ElementType.PARAMETER, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@AuthenticationPrincipal
public @interface CurrentUser {
    /**
     * We’ve created a meta-annotation so that we don’t get too much tied up of with Spring Security related
     * annotations everywhere in our project
     * This reduces the dependency on Spring Security
     * So if we decide to remove Spring Security from our project,
     * we can easily do it by simply changing the CurrentUser annotation
     */
}
