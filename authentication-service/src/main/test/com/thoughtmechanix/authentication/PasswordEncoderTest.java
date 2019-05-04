package com.thoughtmechanix.authentication;

import org.junit.Test;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncoderTest {

    @Test
    public void testBCryptEncode(){
        BCryptPasswordEncoder b = new BCryptPasswordEncoder();
        // encode编码后字符即为BCrypt加密字符
        System.out.println(b.encode("password1"));
        String encodePw = "$2a$04$NX3QTkBJB00upxKeaKqFBeoIVc9JHvwVnj1lItxNphRj34wNx5wlu";
        boolean bool =  b.matches("password1","$2a$10$q5j..SHWKmoCh.asZMrMGeB1P0FOShZFhmXDDIa.7SKywOEHEld9G");
        System.out.println(bool);
    }

    @Test
    public void testBCrypt(){
        // 第一次hash
        String password = "password1";
        String hashed = BCrypt.hashpw(password, BCrypt.gensalt());
        System.out.println("hashed = "+hashed);
        //
        String hashed2 = BCrypt.hashpw(password, BCrypt.gensalt(12));
        System.out.println("hashed2 = "+hashed2);
        String candidate = "password1";

        System.out.println(BCrypt.checkpw(candidate,hashed2));



    }
}
