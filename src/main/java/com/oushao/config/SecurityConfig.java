package com.oushao.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

//AOP横切：拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    //链式编程
    //授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页只有对应有权限的人才能访问
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasAnyRole("vip1")
                .antMatchers("/level2/**").hasAnyRole("vip2")
                .antMatchers("/level3/**").hasAnyRole("vip3");

        //没有权限跳到登录页面
        http.formLogin().loginPage("/toLogin").loginProcessingUrl("/login");
        http.csrf().disable();//关闭防止跨站攻击
        //记住我
        http.rememberMe().rememberMeParameter("remember");
        //注销功能
        http.logout().logoutSuccessUrl("/");
    }
    //认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这些数据应该从数据库拿
        /*
            java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"


         */

        //缓存拿数据
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("oushao").password(new BCryptPasswordEncoder().encode("123456")).roles("vip2","vip3")
                .and().withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3");

        //jdbc拿数据
       /* auth.jdbcAuthentication().dataSource().withDefaultSchema();*/
    }
}
