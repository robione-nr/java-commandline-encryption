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
    private final static int UNDEFINED = 0x0000;
    private final static int ENCRYPT_MODE = 0x0001;
    private final static int DECRYPT_MODE = 0x0002;

    private static HashMap<Character,String> options = new HashMap<>();
    private static int mode = UNDEFINED;
    private static short saltSize = 100;
    private static boolean compression = false;
    private static Path in = null, out = null;

    private static Key key;
    private static char[] phrase;
    private static Salt salt;
    private static byte[] IV = new byte[12];


    public static void main(String[] args) {
        OutputStream ostream = null;        InputStream istream = null;
        BufferedOutputStream bos = null;    BufferedInputStream bis = null;
        GZIPOutputStream gos = null;        GZIPInputStream gis = null;
        FileOutputStream fos = null;        FileInputStream fis = null;
        CipherOutputStream cos = null;      CipherInputStream cis = null;

        byte[] buffer = new byte[1<<14]; //16k
        Cipher cipher = null;

        //***** PARSE COMMANDLINE OPTIONS
        parseArgs(args);
        updateState();

        //***** SETUP ENCRYPTION/DECRYPTION OPERATION
        if(mode ==  ENCRYPT_MODE) {

            char[] confirmation;
            boolean looped = false;
 
            do {
                if(looped) System.console().printf("\nPhrase mismatch. Please try again.\n");

                phrase = System.console().readPassword("Enter Key Phrase: ");
                confirmation = System.console().readPassword("Confirm Phrase: ");

                looped = true;
            } while(!Arrays.equals(phrase, confirmation));

            salt = new Salt(saltSize);
            new SecureRandom().nextBytes(IV);

            try {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                key = AES256Key.getPBK(phrase, salt);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            } catch(Exception e) {
                exit("\nERROR: Could not initialize cipher", null);
            }

            try {
                cos = new CipherOutputStream(
                        bos = new BufferedOutputStream(
                        fos = new FileOutputStream(out.toFile())), cipher);
                
                if(compression) ostream = gos = new GZIPOutputStream(cos);
                else ostream = cos;

                istream = bis = new BufferedInputStream(fis = new FileInputStream(in.toFile()));
            } catch(Exception e) {
                exit("ERROR: Issues encountered while initializing I/O files and streams.", null);
            }
                
            try {
                bos.write(IV);
                bos.write(ByteBuffer.allocate(Short.BYTES).putShort(saltSize).array());
                bos.write(salt.getBytes());
            } catch(Exception e) {
                exit("ERROR: Could not write output file header.", null);
            }

        } else if(mode == DECRYPT_MODE) {

            try {
                bis = new BufferedInputStream(fis = new FileInputStream(in.toFile()));

                bis.read(IV);
                bis.read(buffer,0,Short.BYTES);
                saltSize = ByteBuffer.wrap(buffer,0,Short.BYTES).getShort();
                salt = new Salt(saltSize, false);
                bis.read(salt.getBytes());
            } catch(Exception e) {
                exit("ERROR: Issues encountered while initializing I/O files and streams.", null);
            }

            phrase = System.console().readPassword("Key Phrase: ");

            try {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                key = AES256Key.getPBK(phrase, salt);
                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
                cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);
            } catch(Exception e) {
                exit("\nERROR: Could not initialize cipher", e);
            }

            try {
                cis = new CipherInputStream(bis, cipher);
                if(compression) istream = gis = new GZIPInputStream(cis);
                else    istream = cis;
                
                ostream = bos = new BufferedOutputStream(fos = new FileOutputStream(out.toFile()));
            } catch(Exception e) {
                exit("ERROR: Issues encountered while initializing I/O files and streams.", null);
            }

        } else {
            exit("Undefined internal state.",null);
        }

        //***** EXECUTION
        int length = 0;

        try {
            while((length = istream.read(buffer)) > 0)
                ostream.write(buffer, 0, length);
        } catch(Exception e) {
            exit("ERROR: Issues while performing cipher operations.", null);
        }

        //**** CLEAN UP
        try {
            if(gis != null) gis.close();        if(gos != null) gos.close();
            if(cis != null) cis.close();        if(cos != null) cos.close();
            if(bis != null) bis.close();        if(bos != null) bos.close();
            if(fis != null) fis.close();        if(fos != null) fos.close();
        } catch(Exception e) {
            exit("ERROR: Issue encountered while closing I/O streams.", null);
        }
    }

    private static void exit(String msg, Exception e) {
        System.console().printf("\n%s\n\n",msg);
        if(e != null) e.printStackTrace();
        try{Files.deleteIfExists(out);} catch (Exception _e) {}
        System.exit(0);
    }

    private static void insert(HashMap<Character, String> hm, Character key) {
        insert(hm,key,"");
    }

    private static void insert(HashMap<Character, String> hm, Character key, String value) {
        if(hm.containsKey(key)) usage("Duplicate key: "+key);
        hm.put(key, value);
    }

    private static void updateState() {
        options.forEach((k,v) -> {
            if(k == 'v')        System.console().printf("Java AES-256 GCM Encoder/Decoder V1.1.2\n");
            else if(k == 'z')   compression = true;
            else if(k == 'i')   {
                in = Paths.get(v);
                if(!Files.exists(in)) {
                    System.console().printf("ERROR: The specified input file does not exist.");
                    System.exit(0);
                }
            }
            else if(k == 'o')   out = Paths.get(v);
            else if(k == 'e')   mode = ENCRYPT_MODE;
            else if(k == 'd')   mode = DECRYPT_MODE;
            //Salt size handled during parsing.
        });

        if(out == null)     out = Paths.get("/dev/stdout");
        options.clear();
    }

    private static void parseArgs(String[] args) {
        if(args.length < 3) usage("Missing required arguments.");
        for(int i = 0; i < args.length; ++i)
            if(args[i].charAt(0) == '-') {
                if(args[i].charAt(1) == '-')
                    switch(args[i].substring(2)) {
                        case "version": args[i] = "-v"; break;
                        case "input":   args[i] = "-i"; break;
                        case "output":  args[i] = "-o"; break;
                        case "zip":
                        case "gzip":    args[i] = "-z"; break;
                        case "salt":    args[i] = "-s"; break;
                        case "encrypt": args[i] = "-e"; break;
                        case "decrypt": args[i] = "-d"; break;
                        default:        usage("Unexpected token: "+args[i]);
                    }
    
                i = parseOptions(args, i);
            } else 
                usage("Unexpected token: "+args[i]);
        
        if(!options.containsKey('i') ||
            (!options.containsKey('d') && !options.containsKey('e')))
    
            usage("Missing required arguments.");
    }

    private static int parseOptions(String[] argv, int index) {
        int len, offset = 0, next = index+1;
        for(int i = 1; i < (len = argv[index].length()); ++i)
            switch(argv[index].charAt(i)) {
                case 'v':   insert(options,'v');
                            break;

                case 'i':   if(len > 2)
                                usage("Option (-i) cannot be grouped. Refer to format below.");

                            insert(options,'i',argv[next]);
                            ++offset;
                            break;

                case 'o':   if(len > 2)
                                usage("Option (-o) cannot be grouped. Refer to format below.");

                            insert(options,'o',argv[next]);
                            ++offset;
                            break;

                case 'z':   insert(options,'z');
                            break;

                case 's':   if(len > 2)
                                usage("Option (-s) cannot be grouped. Refer to format below.");
                            
                            try{
                                    saltSize = Short.parseShort(argv[next]);
                                    ++offset;
                            } catch(Exception e) {usage("Unexpected token: "+argv[index]);}

                            if(saltSize < 0) usage("Positive values for salt sizes.");
                            insert(options,'s',argv[next]);
                            break;

                case 'e':   if(options.containsKey('d')) usage("Encryption and decryption are mutually exclusive options.");
                            insert(options,'e');
                            break;

                case 'd':   if(options.containsKey('e')) usage("Encryption and decryption are mutually exclusive options.");
                            insert(options,'d');
                            break;

                default:    usage("Unexpected character '"+argv[index].charAt(i)+"' in token: "+argv[index]);

            }

        return index + offset;
    }

    private static void usage(String msg) {
        if(msg != null)
            System.console().printf("%s\n", msg);

        System.console().printf("\n%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
        "USAGE (class):\t`java <main-class>` [OPTIONS] [2>/dev/null]\n",
        "USAGE (jar):\t`java -jar <jar-file>` [OPTIONS] [2>/dev/null]\n",
        "USAGE: An alias can be defined in your shell's rc file such a\n",
        "       alias encrypt='java -jar <jar-file> -e'\n\n",
        "Options: -e|d[zv] -i <input-file> [-o <output-file>] [-s <integer>]\n\n",
        "    REQUIRED:\n",
        "   -e, --encrypt: Encrypts the input file. Mutually exclusive with decryption.\n",
        "   -d, --decrypt: Decrypts the input file. Mutually exclusive with encryption.\n",
        "   -i, --input: File to receive cipher operation.\n\n",
        "    OPTIONAL:\n",
        "   -z, --[g]zip: Compresses the input file / Decompresses output file using gzip.\n",
        "   -o, --output: Destination file. If none is specified output is\n",
        "                 directed to stdout.\n",
        "   -s, --salt: Salt length in bytes. Defaults to 100. Must be positive.\n",
        "   -v, --version: Version info.\n\n",
        "Note: Grouping is important, not option order.\n\n",
        "Example: `java -jar /usr/local/aes256gcm -ez --salt 256 -i ~/file.txt`\n",
        "    -or- `encrypt --salt 256 --input ~/file.txt --zip`"
        );

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
