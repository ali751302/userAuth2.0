package com.example.userauth2_0.security;





import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

@Component
@Slf4j
public class KeyUtils {

    @Autowired
    Environment environment;

    //These variables taking value from environment variables.
   @Value("${access-token.private}")
    private String accessTokenPrivateKeyPath;

    @Value("${access-token.public}")
    private String accessTokenPublicKeyPath;

    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKeyPath;

    @Value("${refresh-token.public}")
    private String refreshTokenPublicKeyPath;


    //This will allow to read a file once and store in the variables.
    private KeyPair _accessTokenKeyPair;
    private KeyPair _refreshTokenKeyPair;

    //Get Access Token KeyPair Method.
    public KeyPair get_accessTokenKeyPair(){
        if(Objects.isNull(_accessTokenKeyPair)){
            _accessTokenKeyPair = getKeyPair(accessTokenPublicKeyPath , accessTokenPrivateKeyPath);
        }
        return _accessTokenKeyPair;
    }

    public KeyPair get_refreshTokenKeyPair(){
        if(Objects.isNull(_refreshTokenKeyPair)){
            _refreshTokenKeyPair = getKeyPair(refreshTokenPublicKeyPath , refreshTokenPrivateKeyPath);
        }
        return _refreshTokenKeyPair;
    }



    //Then we create a public method for public and private key.
    public RSAPublicKey getAccessTokenPublicKey(){
        return (RSAPublicKey) get_accessTokenKeyPair().getPublic();
    };
    public RSAPrivateKey getAccessTokenPrivateKey(){
        return (RSAPrivateKey) get_accessTokenKeyPair().getPrivate();
    };

    public RSAPublicKey getRefreshTokenPublicKey(){
        return (RSAPublicKey) get_refreshTokenKeyPair().getPublic();
    };
    public RSAPrivateKey getRefreshTokenPrivateKey(){
        return (RSAPrivateKey) get_refreshTokenKeyPair().getPrivate();
    };


    //Generate getKeyPair method, which take publickeypath and privatekeypath as parameters.
    private KeyPair getKeyPair(String publicKeyPath, String privateKeyPath) {
    KeyPair keyPair;
    File publicKeyFile = new File(publicKeyPath);
    File privateKeyFile = new File(privateKeyPath);

    if(publicKeyFile.exists() && privateKeyFile.exists()){
        log.info("Loading Keys From File: {} {}", publicKeyPath, privateKeyPath);
      try{
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");

          byte[] publicKeyByte = Files.readAllBytes(publicKeyFile.toPath());
          EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
          PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);


          byte[] privateKeyByte = Files.readAllBytes(privateKeyFile.toPath());
          PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
          PrivateKey privateKey =  keyFactory.generatePrivate(privateKeySpec);
          keyPair = new KeyPair(publicKey,privateKey);
          return  keyPair;
      }catch (NoSuchAlgorithmException e){
          throw new RuntimeException(e);
      }catch (IOException e){
          throw new RuntimeException(e);
      }catch (InvalidKeySpecException e){
          throw new RuntimeException(e);
      }

    }else{
        if(Arrays.stream(environment.getActiveProfiles()).anyMatch(s -> s.equals("prod"))){
            throw new RuntimeException("Public And Private Key Doesn't Exist.");
        }
      }
    File directory = new File("access-refresh-token-keys");
    if(!directory.exists()){
        directory.mkdirs();
    }
    try{
        log.info("Generating New Public And Private Keys:{} {}" ,publicKeyPath, privateKeyPath );
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        keyPair = keyPairGenerator.generateKeyPair();
        try(FileOutputStream fos = new FileOutputStream(publicKeyPath)){
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
            fos.write(keySpec.getEncoded());
        }

        try(FileOutputStream fos = new FileOutputStream(privateKeyPath)){
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
            fos.write(keySpec.getEncoded());
        }

    } catch (FileNotFoundException e) {
        throw new RuntimeException(e);
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
    } catch (IOException e) {
        throw new RuntimeException(e);
    }
        return keyPair;
    }
}
