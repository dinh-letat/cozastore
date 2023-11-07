package com.cybersoft.cozastore22.security;

import com.cybersoft.cozastore22.filter.JwtFilter;
import com.cybersoft.cozastore22.provider.CustomAuthenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomAuthenProvider customAuthenProvider;

    @Autowired
    private JwtFilter jwtFilter;

    //Khai báo chuẩn mã hóa password và đưa lên IOC
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //Định nghĩa lại authentication manager sử dụng custom provider
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(customAuthenProvider)
                .build();
    }

    //Quy định cấu hình cho Security
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf().disable() //Disable tấn công dạng cross-site vì đang sử dụng API
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //Không sử dụng session
                .and()
                .authorizeHttpRequests()
                    .antMatchers("/user/**").permitAll() //Không cần đăng nhập cũng truy cập được
                    .antMatchers(HttpMethod.POST,"/product").hasRole("ADMIN")
                    .antMatchers(HttpMethod.GET,"/product").hasAnyRole("USER","ADMIN")
                    .anyRequest().authenticated() //Tất cả các request còn lại điều phải chứng thực
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

}
