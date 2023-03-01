/********************************
    Copyright (C) 2023  Nolan Robidoux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 ********************************/
import java.io.Console;

import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;

import java.security.SecureRandom;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKeyFactory;


public class Aes256Gcm {
    private static Key key;
    private static char[] phrase;
    private static Salt salt;
    private static byte[] IV = new byte[12];

    //Helper variables
    private static short saltSize = 100;

    public static void main(String[] args) {
        boolean encrypt = true;
        Path in = null,out = null;

        byte[] content;
        
        //Command line arguments
        for(int i=0; i<args.length; ++i) {
            if(args[i].equals("-d"))        encrypt = false;
            else if(args[i].equals("-e"))   encrypt = true;
            else if(args[i].equals("-s"))   saltSize = Short.parseShort(args[++i]);
            else if(args[i].equals("-i"))   {
                in = Paths.get(args[++i]);
                if(!Files.exists(in))
                    exit("Specified input file invalid.");
            } else if(args[i].equals("-o"))   out = Paths.get(args[++i]);
        }

        //Mop up state
        if(out == null)     out = Paths.get("/dev/stdout");
        if(in == null)      exit("Please specify input file.");

        try {
            //Read in  data
            content = Files.readAllBytes(in);

            if(encrypt) {   //Setup for encryption
                salt = new Salt(saltSize);
                new SecureRandom().nextBytes(IV);

                //Encrypt; Concatonate IV and Salt
                content = encrypt(content);
                content = ByteBuffer.allocate(content.length + saltSize + IV.length + Short.BYTES).
                                put(IV).
                                putShort(saltSize).
                                put(salt.getBytes()).
                                put(content).
                                array();

            } else {        //Setup for decryption
                ByteBuffer buffer = ByteBuffer.wrap(content);

                buffer.get(IV);
                saltSize = buffer.getShort();
                salt = new Salt(saltSize, false);
                content = new byte[content.length - saltSize - IV.length - Short.BYTES];

                buffer.get(salt.getBytes());
                buffer.get(content);

                //Decrypt
                content = decrypt(content);
            }

            //Write to file
            Files.write(out, content);

        } catch (Exception e) {
            e.printStackTrace();
        }        
    }

    public static byte[] encrypt(byte[] plainText) {
        try {
            char[] confirmation;

            //Retrieve key phrase from user; Exit if mismatch
            phrase = System.console().readPassword("Key Phrase: ");
            confirmation = System.console().readPassword("Confirm: ");

            if(!Arrays.equals(phrase, confirmation))
                exit("Phrase mismatch.");

            //Encrypt
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            key = AES256Key.getPBK(phrase, salt);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

            return cipher.doFinal(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public static byte[] decrypt(byte[] cipherText) {
        try {
            phrase = System.console().readPassword("Key Phrase: ");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            key = AES256Key.getPBK(phrase, salt);
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
            cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
        
            return cipher.doFinal(cipherText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static void exit(String message) {
        System.out.println(message);
        System.exit(0);
    }

}

class Salt {
    Salt(int size, boolean init)    {initialize(size, init);}
    Salt(int size)                  {this(size, true);}
    Salt()                          {this(100, true);}

    private byte[] data;

    public byte[] getBytes() {return data;}

    private void initialize(int size, boolean init) {
        data = new byte[size];

        if(init)
            new SecureRandom().nextBytes(data);
    }
}

class AES256Key {
    static Key getPBK(char[] phrase, Salt salt) {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(phrase, salt.getBytes(), 1000, 256);
            SecretKey pbeKey = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(pbeKeySpec);
            return new SecretKeySpec(pbeKey.getEncoded(), "AES");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
