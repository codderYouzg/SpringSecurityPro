package com.youzg.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @Author: Youzg
 * @CreateTime: 2020-07-01 08:55
 * @Description: 带你深究Java的本质！
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 授权
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 首页所有人都能访问，功能页只有对拥有权限的人才能访问
        // 请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()   // 允许所有
                .antMatchers("/level1/**").hasRole("vip1")  // 允许指定的
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        // 没有权限，默认跳转到“登陆页面”
        http.formLogin().loginPage("/toLogin").failureForwardUrl("/loginError");

        // 防止网站攻击(get请求，明文反馈)
        // SpringBoot默认 配置好 防止CSRF攻击(post请求不会出现该问题)
        http.csrf().disable();  // 关闭csrf攻击

        // 注销，开启注销功能
        // 注销成功后，跳转的页面
        http.logout().logoutSuccessUrl("/");
        //http.logout().deleteCookies("remove").invalidateHttpSession(true);  // 清空所有cookie和session

         //开启“记住我”功能    cookie实现，默认14天(两周)
        http.rememberMe().rememberMeParameter("remember");
    }

    // 认证
    // 密码编码：PasswordEncoder
    // 在Spring Secutiry 5.0+ 新增了很多加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                // 以下数据应该从数据库中读
                .withUser("liuxiansen").password(new BCryptPasswordEncoder().encode("159357")).roles("vip1", "vip3")
                .and()
                .withUser("youzg").password(new BCryptPasswordEncoder().encode("357159")).roles("vip1", "vip2", "vip3");
    }
}
