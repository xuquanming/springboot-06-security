package com.company.config;


import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


//AOP 拦截器
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //链式编程
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人可以访问，功能页只有对应有权限的人才能访问
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //没有权限默认会到登录页面,需要开启登录的页面
        //   /login  security的登录页面
        http.formLogin().loginPage("/toLogin").usernameParameter("username").passwordParameter("password").loginProcessingUrl("/login");

        //防止网站攻击：get，post
        http.csrf().disable();
        //注销.开启了注销功能,跳到首页
        http.logout().logoutSuccessUrl("/");

        //开启记住我功能 cookie  默认保存两周  自定义接收前端的参数
        http.rememberMe().rememberMeParameter("remember");
    }

    //认证
    //密码编码：PasswordEncoder
    //在spring Security  5.0＋  新增了很多的加密方法
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        /*auth.jdbcAuthentication()
                .dataSource(dataSource)
                .withDefaultSchema()
                .withUser()*/
        //这些数据正常应该从数据库中读
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("ming").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP2","VIP3")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2","VIP3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1");
    }
}
