package com.company;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {
            AES_ENCRYPTION aes_encryption = new AES_ENCRYPTION();
            Digital_Signature digital_signature = new Digital_Signature();
            Scanner scanner = new Scanner(System.in);


            while (true) {
                System.out.println("Do you need to send file or message ? [F-File , M-Message] :");
                String type = scanner.nextLine();
                if (type.equals("F")) {
                    digital_signature.init();
                    System.out.println("Type a file path :");
                    String file_path = scanner.nextLine();
                    String digitalSignature = digital_signature.documentSign(file_path);
                    System.out.println("Digital Signature :"+digitalSignature);
                    System.out.println("Do you need send ? [Y-Yes , N-No ] :");
                    String send = scanner.nextLine();
                    if (send.equals("Y")) {
                        boolean verified = false;
                        while (!verified) {
                            System.out.println("Type a file path :");
                            String file = scanner.nextLine();
                            System.out.println("Enter the digital signature:");
                            String dSignature = scanner.nextLine();
                            boolean isCorrect = digital_signature.SignatureVerification(file,dSignature);
                            if(isCorrect){
                                System.out.println("verified");
                                verified = !verified;
                            }else{
                                System.out.println("invalid signature");
                            }
                        }
                    }
                } else {
                    System.out.println("Enter your string :");
                    String input_string = scanner.nextLine();
                    aes_encryption.init();
                    String signature = aes_encryption.encrypt(input_string);
                    System.out.println("Generated signature : " + signature);
                    System.out.println("Do you need send ? [Y-Yes , N-No ] :");
                    String answer = scanner.nextLine();
                    if (answer.equals("Y")) {
                        boolean verified = false;
                        while (!verified) {
                            System.out.println("Enter the signature:");
                            try {
                                String secret_signature = scanner.nextLine();
                                String decrypt_string = aes_encryption.decrypt(secret_signature);

                                if (input_string.equals(decrypt_string)) {
                                    System.out.println("verified");
                                    verified = !verified;
                                } else {
                                    System.out.println("invalid signature");
                                }
                            } catch (Exception exception) {
                                System.out.println("invalid signature");
                            }
                        }


                    }
                }
                System.out.println("Do you need to exit? [Y-Yes, N-No] :");
                String exit = scanner.nextLine();
                if (exit.equals("Y")) {
                    return;
                }

            }
        }catch (Exception exception) {
            System.out.println("Exception :" + exception.getMessage());
        }
    }
}
class Digital_Signature{
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public void init() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public String documentSign(String filePath) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        byte[] messageBytes = Files.readAllBytes(Paths.get(filePath));
        signature.update(messageBytes);
        byte[] digitalSignature = signature.sign();
        return encode(digitalSignature);
    }

    public boolean SignatureVerification(String filePath, String digitalSignature) throws Exception{
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        byte[] messageBytes = Files.readAllBytes(Paths.get(filePath));
        signature.update(messageBytes);
        byte[] receivedSignature = decode(digitalSignature);
        boolean isCorrect = signature.verify(receivedSignature);
        return isCorrect;
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
class AES_ENCRYPTION {

    private final int DATA_LENGTH = 128;
    private Cipher encryptionCipher;
    private final int KEY_SIZE = 128;
    private SecretKey key;

    public void init() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();
    }

    public String encrypt(String data) throws Exception {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

}
