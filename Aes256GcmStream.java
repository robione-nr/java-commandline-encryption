/*********************************
    Copyright (C) 2023  Nolan Robidoux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

*********************************/
import java.io.Console;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
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
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;


public class Aes256GcmStream {
    private static Key key;
    private static char[] phrase;
    private static Salt salt;
    private static byte[] IV = new byte[12];

    //Helper variables
    private static short saltSize = 100;

    public static void main(String[] args) {
        OutputStream ostream = null;        InputStream istream = null;
        BufferedOutputStream bos = null;    BufferedInputStream bis = null;
        GZIPOutputStream gos = null;        GZIPInputStream gis = null;
        FileOutputStream fos = null;        FileInputStream fis = null;
        CipherOutputStream cos = null;      CipherInputStream cis = null;

        boolean encrypt = true, zip = false;
        Path in = null,out = null;

        byte[] buffer = new byte[1<<14]; //16k
       
        try {
            //Command line arguments
            for(int i=0; i<args.length; ++i) {
                if(args[i].equals("-d"))        encrypt = false;
                else if(args[i].equals("-e"))   encrypt = true;
                else if(args[i].equals("-z"))   zip = true;
                else if(args[i].equals("-s"))   saltSize = Short.parseShort(args[++i]);
                else if(args[i].equals("-i"))   {
                    in = Paths.get(args[++i]);
                    if(!Files.exists(in)) throw new FileNotFoundException("The specified input file does not exist.");
                }
                else if(args[i].equals("-o"))   out = Paths.get(args[++i]);
                else if(args[i].equals("-v"))   System.console().printf("Java AES-256 GCM Encoder/Decoder V1.1\n");
                else {
                    System.console().printf("%s\n\n%s\n\n%s\n\t%s\n\t%s\n\n%s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n",
                        "USAGE: `java 'aes-class-name'.java` [OPTIONS] [2>/dev/null]",
                        "USAGE: `java -jar 'jar-file'` [OPTIONS] [2>/dev/null]",
                        "USAGE: Using an aliased example (Used as above with `-d/-e` ---",
                        "`encrypt -i <file> -o <file>`",
                        "`decrypt -i <file> -o <file>`",
                        "Options:",
                        "-d/-e: Mutually exclusive. Encrypt or decrypt the input file.",
                        "-i <input-file>: Required. File to be de-/en-crypted.",
                        "-o <output-file>: Required. Destination file. (Default: stdout)",
                        "-s <integer>: Salt length in bytes. Default 100.",
                        "-v: Version info.");
                    System.exit(0);
                }
            }

            //Mop up state
            if(out == null)     out = Paths.get("/dev/stdout");
            if(in == null)      throw new FileNotFoundException("Please specify an input file.");

            if(encrypt) {   //**** ENCRYPT SETUP *****//
                //Setup Passphrase
                char[] confirmation;
                boolean looped = false;

                do {
                    if(looped) System.console().printf("\nPhrase mismatch. Please try again.\n");

                    phrase = System.console().readPassword("Enter Key Phrase: ");
                    confirmation = System.console().readPassword("Confirm Phrase: ");

                    looped = true;
                } while(!Arrays.equals(phrase, confirmation));

                //Setup encryption and prepare output
                salt = new Salt(saltSize);
                new SecureRandom().nextBytes(IV);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                key = AES256Key.getPBK(phrase, salt);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);

                cos = new CipherOutputStream(
                        bos = new BufferedOutputStream(
                        fos = new FileOutputStream(out.toFile())), cipher);
                
                if(zip) ostream = gos = new GZIPOutputStream(cos);
                else ostream = cos;

                istream = bis = new BufferedInputStream(fis = new FileInputStream(in.toFile()));
                
                bos.write(IV);
                bos.write(ByteBuffer.allocate(Short.BYTES).putShort(saltSize).array());
                bos.write(salt.getBytes());

            } else {    //***** DECRYPTION SETUP  *****/
                
                bis =   new BufferedInputStream(fis = new FileInputStream(in.toFile()));

                bis.read(IV);
                bis.read(buffer,0,Short.BYTES);
                saltSize = ByteBuffer.wrap(buffer,0,Short.BYTES).getShort();
                salt = new Salt(saltSize, false);
                bis.read(salt.getBytes());

                //Decrypt
                phrase = System.console().readPassword("Key Phrase: ");

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                key = AES256Key.getPBK(phrase, salt);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

                cis = new CipherInputStream(bis, cipher);
                if(zip) istream = gis = new GZIPInputStream(cis);
                else    istream = cis;
                
                ostream = bos = new BufferedOutputStream(fos = new FileOutputStream(out.toFile()));
            }

            //***** EXECUTION
            int length = 0;

            while((length = istream.read(buffer)) > 0)
                ostream.write(buffer, 0, length);

            //**** CLEAN UP
            if(gis != null) gis.close();        if(gos != null) gos.close();
            if(cis != null) cis.close();        if(cos != null) cos.close();
            if(bis != null) bis.close();        if(bos != null) bos.close();
            if(fis != null) fis.close();        if(fos != null) fos.close();
        } catch (Exception e) {
            e.printStackTrace();
            try{Files.deleteIfExists(out);} catch (Exception _e) {}
        }        
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
