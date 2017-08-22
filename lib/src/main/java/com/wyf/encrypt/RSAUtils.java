package com.wyf.encrypt;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Created by wyf on 2017/8/22.
 *
 * RSA加密和解密工具类
 */
public class RSAUtils {

    public static final String RSA = "RSA";// 非对称加密密钥算法
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";// 加密填充方式
    public static final int DEFAULT_KEY_SIZE = 1024;// 秘钥默认长度

    private RSAUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    /**
     * 随机生成RSA密钥对
     *
     * @param keyLength 密钥长度，范围：512～2048 一般1024
     * @return 密钥对
     */
    public static KeyPair generateRSAKeyPair(int keyLength) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA);
            kpg.initialize(keyLength);
            return kpg.genKeyPair();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return 私钥
     */
    public static PrivateKey getPrivateKey(String privateKey) {
        return getPrivateKey(Base64.decode(privateKey));
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥数据
     * @return 私钥
     */
    public static PrivateKey getPrivateKey(byte[] privateKey) {
        // 得到私钥
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(RSA);
            PrivateKey keyPrivate = kf.generatePrivate(keySpec);
            return keyPrivate;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return 公钥
     */
    public static PublicKey getPublicKey(String publicKey) {
        return getPublicKey(Base64.decode(publicKey));
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥数据
     * @return 公钥
     */
    public static PublicKey getPublicKey(byte[] publicKey) {
        // 得到公钥
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance(RSA);
            PublicKey keyPublic = kf.generatePublic(keySpec);
            return keyPublic;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // ====================================================================================
    //                                      私钥解密
    // ====================================================================================

    /**
     * 解密RSA公钥加密过符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param privateKey 私钥字符串
     * @param encrypted 加密的数据
     * @return 解密后的字符串
     * @throws Exception 异常
     */
    public static String decryptFromNetByPrivateKey(String privateKey, String encrypted) throws Exception {
        return decryptFromNetByPrivateKey(getPrivateKey(privateKey), encrypted);
    }

    /**
     * 解密RSA公钥加密过符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param privateKey 私钥
     * @param encrypted 加密的数据
     * @return 解密后的字符串
     * @throws Exception 异常
     */
    public static String decryptFromNetByPrivateKey(PrivateKey privateKey, String encrypted) throws Exception {
        encrypted = encrypted.replace("-", "+").replace("_", "/");
        int mod4 = encrypted.length() / 4;
        for (int i = 0; i < mod4; i++) {
            encrypted += "=";
        }
        Log.e("=====", encrypted);
        return decryptByPrivateKey(privateKey, encrypted);
    }

    /**
     * 解密RSA公钥加密过的数据
     *
     * @param privateKey 私钥字符串
     * @param encrypted 加密的字符串
     * @return 解密后的字符串
     * @throws Exception 异常
     */
    public static String decryptByPrivateKey(String privateKey, String encrypted) throws Exception {
        return new String(decryptByPrivateKey(getPrivateKey(privateKey), Base64.decode(encrypted)));
    }

    /**
     * 解密RSA公钥加密过的数据
     *
     * @param privateKey 私钥
     * @param encrypted 加密的字符串
     * @return 解密后的字符串
     * @throws Exception 异常
     */
    public static String decryptByPrivateKey(PrivateKey privateKey, String encrypted) throws Exception {
        return new String(decryptByPrivateKey(privateKey, Base64.decode(encrypted)));
    }

    /**
     * 解密RSA公钥加密过的数据
     *
     * @param privateKey 私钥字符串
     * @param encryptedData 加密的数据
     * @return 解密后的数据
     * @throws Exception 异常
     */
    public static byte[] decryptByPrivateKey(String privateKey, byte[] encryptedData) throws Exception {
        return decryptByPrivateKey(getPrivateKey(privateKey), encryptedData);
    }

    /**
     * 解密RSA公钥加密过的数据
     *
     * @param privateKey 私钥
     * @param encryptedData 加密的数据
     * @return 解密后的数据
     * @throws Exception 异常
     */
    public static byte[] decryptByPrivateKey(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(2, privateKey);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int max = DEFAULT_KEY_SIZE / 8;
        for (int i = 0; inputLen - offSet > 0; offSet = i * max) {
            byte[] cache;
            if (inputLen - offSet > max) {
                cache = cipher.doFinal(encryptedData, offSet, max);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    // ======================================================================================
    //                                  公钥解密
    // ======================================================================================

    /**
     * 解密RSA私钥加密过符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param publicKey 公钥字符串
     * @param encryptedData 加密的字符串
     * @return 解密的字符串
     * @throws Exception 异常
     */
    public static String decryptFromNetByPublicKey(String publicKey, String encryptedData) throws Exception {
        return decryptFromNetByPublicKey(getPublicKey(publicKey), encryptedData);
    }

    /**
     * 解密RSA私钥加密过符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param publicKey 公钥
     * @param encryptedData 加密的字符串
     * @return 解密的字符串
     * @throws Exception 异常
     */
    public static String decryptFromNetByPublicKey(PublicKey publicKey, String encryptedData) throws Exception {
        encryptedData = encryptedData.replace("-", "+").replace("_", "/");
        int mod4 = encryptedData.length() / 4;
        for (int i = 0; i < mod4; i++) {
            encryptedData += "=";
        }
        return decryptByPublicKey(publicKey, encryptedData);
    }

    /**
     * 解密RSA私钥加密过的数据
     *
     * @param publicKey 公钥字符串
     * @param encryptedData 加密的字符串
     * @return 解密的字符串
     * @throws Exception 异常
     */
    public static String decryptByPublicKey(String publicKey, String encryptedData) throws Exception {
        return new String(decryptByPublicKey(getPublicKey(publicKey), Base64.decode(encryptedData)));
    }

    /**
     * 解密RSA私钥加密过的数据
     *
     * @param publicKey 公钥
     * @param encryptedData 加密的字符串
     * @return 解密的字符串
     * @throws Exception 异常
     */
    public static String decryptByPublicKey(PublicKey publicKey, String encryptedData) throws Exception {
        return new String(decryptByPublicKey(publicKey, Base64.decode(encryptedData)));
    }

    /**
     * 解密RSA私钥加密过的数据
     *
     * @param publicKey 公钥字符串
     * @param encryptedData 加密的数据
     * @return 解密的数据
     * @throws Exception 异常
     */
    public static byte[] decryptByPublicKey(String publicKey, byte[] encryptedData) throws Exception {
        return decryptByPublicKey(getPublicKey(publicKey), encryptedData);
    }

    /**
     * 解密RSA私钥加密过的数据
     *
     * @param publicKey 公钥
     * @param encryptedData 加密的数据
     * @return 解密的数据
     * @throws Exception 异常
     */
    public static byte[] decryptByPublicKey(PublicKey publicKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(2, publicKey);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int max = DEFAULT_KEY_SIZE / 8;
        for (int i = 0; inputLen - offSet > 0; offSet = i * max) {
            byte[] cache;
            if (inputLen - offSet > max) {
                cache = cipher.doFinal(encryptedData, offSet, max);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    // ====================================================================================
    //                                      私钥加密
    // ====================================================================================

    /**
     * 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""）
     *
     * @param privateKey 私钥字符串
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static String encrypt2NetByPrivateKey(String privateKey, String data) throws Exception {
        return encryptByPrivateKey(privateKey, data).replace("+", "-").replace("/", "_").replace("=", "");
    }

    /**
     * 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""）
     *
     * @param privateKey
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static String encrypt2NetByPrivateKey(PrivateKey privateKey, String data) throws Exception {
        return encryptByPrivateKey(privateKey, data).replace("+", "-").replace("/", "_").replace("=", "");
    }

    /**
     * 私钥加密数据
     *
     * @param privateKey 私钥
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static String encryptByPrivateKey(String privateKey, String data) throws Exception {
        return new String(encryptByPrivateKey(privateKey, data.getBytes()));
    }

    /**
     * 私钥加密数据
     *
     * @param privateKey 私钥
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static String encryptByPrivateKey(PrivateKey privateKey, String data) throws Exception {
        return new String(encryptByPrivateKey(privateKey, data.getBytes()));
    }

    /**
     * 私钥加密数据
     *
     * @param privateKey 私钥字符串
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static byte[] encryptByPrivateKey(String privateKey, byte[] data) throws Exception {
        return encryptByPrivateKey(getPrivateKey(privateKey), data);
    }

    /**
     * 私钥加密数据
     *
     * @param privateKey 私钥
     * @param data 数据
     * @return 加密后的数据
     * @throws Exception 异常
     */
    public static byte[] encryptByPrivateKey(PrivateKey privateKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(1, privateKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int max = DEFAULT_KEY_SIZE / 8 - 11;
        for (int i = 0; inputLen - offSet > 0; offSet = i * max) {
            byte[] cache;
            if (inputLen - offSet > max) {
                cache = cipher.doFinal(data, offSet, max);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    // ========================================================================================
    //                                      公钥加密
    // ========================================================================================

    /**
     * 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param publicKey 公钥字符串
     * @param data 待加密的字符串
     * @return 加密后的字符串
     * @throws Exception 异常
     */
    public static String encrypt2NetByPublicKey(String publicKey, String data) throws Exception {
        return encryptByPublicKey(publicKey, data).replace("+", "-").replace("/", "_").replace("=", "");
    }

    /**
     * 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")
     *
     * @param publicKey 公钥
     * @param data 待加密的字符串
     * @return 加密后的字符串
     * @throws Exception 异常
     */
    public static String encrypt2NetByPublicKey(PublicKey publicKey, String data) throws Exception {
        return encryptByPublicKey(publicKey, data).replace("+", "-").replace("/", "_").replace("=", "");
    }

    /**
     * 公钥加密数据
     *
     * @param publicKey 公钥字符串
     * @param data 待加密的字符串
     * @return 加密后字符串
     * @throws Exception 异常
     */
    public static String encryptByPublicKey(String publicKey, String data) throws Exception {
        return Base64.encode(encryptByPublicKey(getPublicKey(publicKey), data.getBytes()));
    }

    /**
     * 公钥加密数据
     *
     * @param publicKey 公钥
     * @param data 待加密的字符串
     * @return 加密后字符串
     * @throws Exception 异常
     */
    public static String encryptByPublicKey(PublicKey publicKey, String data) throws Exception {
        return Base64.encode(encryptByPublicKey(publicKey, data.getBytes()));
    }

    /**
     * 公钥加密数据
     *
     * @param publicKey 公钥字符串
     * @param data 待加密的数据
     * @return 加密后的数据
     * @throws Exception 解密异常
     */
    public static byte[] encryptByPublicKey(String publicKey, byte[] data) throws Exception {
        return encryptByPublicKey(getPublicKey(publicKey), data);
    }

    /**
     * 公钥加密数据
     *
     * @param publicKey 公钥
     * @param data 待加密的数据
     * @return 加密后的数据
     * @throws Exception 解密异常
     */
    public static byte[] encryptByPublicKey(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(1, publicKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        int max = DEFAULT_KEY_SIZE / 8 - 11;
        for (int i = 0; inputLen - offSet > 0; offSet = i * max) {
            byte[] cache;
            if (inputLen - offSet > max) {
                cache = cipher.doFinal(data, offSet, max);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            ++i;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

}
