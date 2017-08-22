package com.wyf;

import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.wyf.encrypt.AESUtils;
import com.wyf.encrypt.DESUtils;
import com.wyf.encrypt.HexUtils;
import com.wyf.encrypt.MD5Utils;
import com.wyf.encrypt.RSAUtils;
import com.wyf.encrypt.SHA1Utils;
import com.wyf.encrypt.SHA256Utils;
import com.wyf.encrypt.SHA384Utils;
import com.wyf.encrypt.SHA512Utils;
import com.wyf.encrypt.DES3Utils;

import java.io.File;
import java.io.IOException;

public class SampleActivity extends AppCompatActivity {

    TextView tv;
    File file;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);
        tv = (TextView) findViewById(R.id.tv);
        if (Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState())
                && getExternalCacheDir() != null)
            file = new File(getExternalCacheDir(), "test.txt");
        else {
            file = new File(getCacheDir(), "test.txt");
        }
        try {
            if (!file.exists()) file.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void onClickAES(View v) {
        tv.append("================AES================\n");
        byte[] key = "aaaabbbbccccddddeeeeffff".getBytes();
        String data = "abcda";
        tv.append("key->" + new String(key) + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = AESUtils.encrypt(data.getBytes(), key);
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = new String(AESUtils.encrypt2Base64(data.getBytes(), key));
        tv.append("encrypt2Base64->" + s2 + "\n");
        String s3 = AESUtils.encrypt2HexString(data.getBytes(), key);
        tv.append("encrypt2HexString->" + s3 + "\n");
        String s11 = new String(AESUtils.decrypt(s1, key));
        tv.append("decrypt->" + s11 + "\n");
        String s22 = new String((AESUtils.decryptBase64(s2.getBytes(), key)));
        tv.append("decryptBase64->" + s22 + "\n");
        String s33 = new String(AESUtils.decryptHexString(s3, key));
        tv.append("decryptHexString->" + s33 + "\n");
    }

    public void onClick3DES(View v) {
        tv.append("================3DES================\n");
        String data = "aaaa";
        String key = "aaaabbbbaaaaccccaaaadddd";
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = DES3Utils.encrypt(data.getBytes(), key.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        byte[] s2 = DES3Utils.encrypt2Base64(data.getBytes(), key.getBytes());
        tv.append("encrypt2Base64->" + new String(s2) + "\n");
        String s3 = DES3Utils.encrypt2HexString(data.getBytes(), key.getBytes());
        tv.append("encrypt2HexString->" + s3 + "\n");
        byte[] s4 = DES3Utils.decrypt(s1, key.getBytes());
        tv.append("decrypt->" + new String(s4) + "\n");
        byte[] s5 = DES3Utils.decryptBase64(s2, key.getBytes());
        tv.append("decryptBase64->" + new String(s5) + "\n");
        byte[] s6 = DES3Utils.decryptHexString(s3, key.getBytes());
        tv.append("decryptHexString->" + new String(s6) + "\n");
    }

    public void onClickDES(View v) {
        tv.append("================DES================\n");
        byte[] key = "aaaabbbb".getBytes();
        String data = "abc";
        tv.append("key->" + new String(key) + "\n");
        tv.append("data->" + data + "\n");
        DESUtils.encrypt(data.getBytes(), key);
        byte[] s1 = DESUtils.encrypt(data.getBytes(), key);
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = new String(DESUtils.encrypt2Base64(data.getBytes(), key));
        tv.append("encrypt2Base64->" + s2 + "\n");
        String s3 = DESUtils.encrypt2HexString(data.getBytes(), key);
        tv.append("encrypt2HexString->" + s3 + "\n");
        String s11 = new String(DESUtils.decrypt(s1, key));
        tv.append("decrypt->" + s11 + "\n");
        String s22 = new String((DESUtils.decryptBase64(s2.getBytes(), key)));
        tv.append("decryptBase64->" + s22 + "\n");
        String s33 = new String(DESUtils.decryptHexString(s3, key));
        tv.append("decryptHexString->" + s33 + "\n");
    }

    public void onClickMD5(View v) {
        tv.append("================MD5================\n");
        String salt = "asdf";
        String key = "sadfgas";
        String data = "abcdac";
        tv.append("salt->" + salt + "\n");
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = MD5Utils.encrypt(data.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = MD5Utils.encrypt2String(data.getBytes());
        tv.append("encrypt2String->" + s2 + "\n");
        String s3 = MD5Utils.encrypt2String(data.getBytes(), salt.getBytes());
        tv.append("encrypt2String->" + s3 + "\n");
        String s4 = MD5Utils.encrypt2String(data, salt);
        tv.append("encrypt2String->" + s4 + "\n");
        byte[] s5 = MD5Utils.encryptFile(file);
        tv.append("encryptFile->" + HexUtils.bytes2HexString(s5) + "\n");
        byte[] s6 = MD5Utils.encryptFile(file.getAbsolutePath());
        tv.append("encryptFile->" + HexUtils.bytes2HexString(s6) + "\n");
        String s7 = MD5Utils.encryptFile2String(file);
        tv.append("encryptFile2String->" + s7 + "\n");
        String s8 = MD5Utils.encryptFile2String(file.getAbsolutePath());
        tv.append("encryptFile2String->" + s8 + "\n");
        byte[] s9 = MD5Utils.encryptHmac(data.getBytes(), key.getBytes());
        tv.append("encryptHmac->" + HexUtils.bytes2HexString(s9) + "\n");
        String s10 = MD5Utils.encryptHmac2String(data.getBytes(), key.getBytes());
        tv.append("encryptHmac2String->" + s10 + "\n");
        String s11 = MD5Utils.encryptHmac2String(data, key);
        tv.append("encryptHmac2String->" + s11 + "\n");
    }

    public void onClickRSA(View v) {
        tv.append("================RSA================\n");
        String data = "asdf";
        tv.append("data->" + data + "\n");
        try {
            byte[] s1 = RSAUtils.encryptByPrivateKey(PRIVATE_KEY, data.getBytes());
            tv.append("encryptByPrivateKey->" + HexUtils.bytes2HexString(s1) + "\n");
            String s2 = RSAUtils.encryptByPublicKey(PUBLIC_KEY, data);
            tv.append("encryptByPublicKey->" + s2 + "\n");
            String s3 = RSAUtils.encrypt2NetByPublicKey(PUBLIC_KEY, data);
            tv.append("encrypt2NetByPublicKey->" + s3 + "\n");
            String s4 = RSAUtils.decryptByPrivateKey(PRIVATE_KEY, s2);
            tv.append("decryptByPrivateKey->" + s4 + "\n");
            String s5 = RSAUtils.decryptFromNetByPrivateKey(PRIVATE_KEY, s3);
            tv.append("decryptFromNetByPrivateKey->" + s5 + "\n");
            byte[] s6 = RSAUtils.decryptByPublicKey(PUBLIC_KEY, s1);
            tv.append("decryptByPublicKey->" + new String(s6) + "\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void onClickSHA1(View v) {
        tv.append("================SHA1================\n");
        String data = "aaaa";
        String key = "sava";
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = SHA1Utils.encrypt(data.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = SHA1Utils.encrypt2String(data.getBytes());
        tv.append("encrypt2String->" + s2 + "\n");
        String s3 = SHA1Utils.encrypt2String(data);
        tv.append("encrypt2String->" + s3 + "\n");
        byte[] s4 = SHA1Utils.encryptHmac(data.getBytes(), key.getBytes());
        tv.append("encryptHmac->" + HexUtils.bytes2HexString(s4) + "\n");
        String s5 = SHA1Utils.encryptHmac2String(data.getBytes(), key.getBytes());
        tv.append("encryptHmac2String->" + s5 + "\n");
        String s6 = SHA1Utils.encryptHmac2String(data, key);
        tv.append("encryptHmac2String->" + s6 + "\n");
    }

    public void onClickSHA256(View v) {
        tv.append("================SHA256================\n");
        String data = "aaaa";
        String key = "sava";
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = SHA256Utils.encrypt(data.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = SHA256Utils.encrypt2String(data.getBytes());
        tv.append("encrypt2String->" + s2 + "\n");
        String s3 = SHA256Utils.encrypt2String(data);
        tv.append("encrypt2String->" + s3 + "\n");
        byte[] s4 = SHA256Utils.encryptHmac(data.getBytes(), key.getBytes());
        tv.append("encryptHmac->" + HexUtils.bytes2HexString(s4) + "\n");
        String s5 = SHA256Utils.encryptHmac2String(data.getBytes(), key.getBytes());
        tv.append("encryptHmac2String->" + s5 + "\n");
        String s6 = SHA256Utils.encryptHmac2String(data, key);
        tv.append("encryptHmac2String->" + s6 + "\n");
    }

    public void onClickSHA384(View v) {
        tv.append("================SHA384================\n");
        String data = "aaaa";
        String key = "sava";
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = SHA384Utils.encrypt(data.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = SHA384Utils.encrypt2String(data.getBytes());
        tv.append("encrypt2String->" + s2 + "\n");
        String s3 = SHA384Utils.encrypt2String(data);
        tv.append("encrypt2String->" + s3 + "\n");
        byte[] s4 = SHA384Utils.encryptHmac(data.getBytes(), key.getBytes());
        tv.append("encryptHmac->" + HexUtils.bytes2HexString(s4) + "\n");
        String s5 = SHA384Utils.encryptHmac2String(data.getBytes(), key.getBytes());
        tv.append("encryptHmac2String->" + s5 + "\n");
        String s6 = SHA384Utils.encryptHmac2String(data, key);
        tv.append("encryptHmac2String->" + s6 + "\n");
    }

    public void onClickSHA512(View v) {
        tv.append("================SHA512================\n");
        String data = "aaaa";
        String key = "sava";
        tv.append("key->" + key + "\n");
        tv.append("data->" + data + "\n");
        byte[] s1 = SHA512Utils.encrypt(data.getBytes());
        tv.append("encrypt->" + HexUtils.bytes2HexString(s1) + "\n");
        String s2 = SHA512Utils.encrypt2String(data.getBytes());
        tv.append("encrypt2String->" + s2 + "\n");
        String s3 = SHA512Utils.encrypt2String(data);
        tv.append("encrypt2String->" + s3 + "\n");
        byte[] s4 = SHA512Utils.encryptHmac(data.getBytes(), key.getBytes());
        tv.append("encryptHmac->" + HexUtils.bytes2HexString(s4) + "\n");
        String s5 = SHA512Utils.encryptHmac2String(data.getBytes(), key.getBytes());
        tv.append("encryptHmac2String->" + s5 + "\n");
        String s6 = SHA512Utils.encryptHmac2String(data, key);
        tv.append("encryptHmac2String->" + s6 + "\n");
    }

    public void onClickClear(View v) {
        tv.setText("");
    }

    public static final String PUBLIC_KEY =
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQChjt842ASFf1VIX39cy11GaiXI" +
            "HNtQiqCvksmoQfF/nV5pjWq9UtQu3BP3iMrXwkB+fDe2JgA2S02gH9KCi2iQXPx1" +
            "QEFDJmfLnIEi+KF8ZTtiC460NRvQYvX96o1w2qb38D61w+50I3onq18mZKIEODlR" +
            "+fXRdeGg65TwEsEu/wIDAQAB";
    public static final String PRIVATE_KEY =
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKGO3zjYBIV/VUhf" +
            "f1zLXUZqJcgc21CKoK+SyahB8X+dXmmNar1S1C7cE/eIytfCQH58N7YmADZLTaAf" +
            "0oKLaJBc/HVAQUMmZ8ucgSL4oXxlO2ILjrQ1G9Bi9f3qjXDapvfwPrXD7nQjeier" +
            "XyZkogQ4OVH59dF14aDrlPASwS7/AgMBAAECgYBLi1g7517t4aXKSsVuabW6+GWk" +
            "VkIDPl922eer4vH/H2IHb1YrIzEOnGBFzlQzYaTwwDr41Hoi6UFqD5dK7c89e9LM" +
            "3GFosR2py5TTrm6d0mZxSB0rrYomH6sCbGI4yM1ozkGKfdMC8BPPT4Xt0ujOzgFe" +
            "s/hSYKlIHbcRLoR26QJBAM9q74twS8pJ56sV8SIlpU0a+sgShFXH3gVZkwKqpO+w" +
            "7pfdqATix4NZEPTFGqle6F+mifJCLV5zH3kIC2TrdXMCQQDHZiCXXfwkYtWfadBq" +
            "G7yfAxN6u55cd9y7JYbN0SCEDMUwoRIHV8mA6/07THhfggPFqLh/Zu8kPaNhXX69" +
            "8Z1FAkEAwF8uwsWpFXoMCspz9baypFvEgjFiWWjgy1dzmMKJ7ODNuT5Uagum/XRq" +
            "3Im+m52xqZz9ThoAmBvv8cH7R2N2bwJAPiNGTsVcGN6v4ZCxARAJtKfZvyqOjBRS" +
            "NgPYwXTFJEFyhdf77UvfIIzqCjunW2QB1uvgKtuh9HI84s+m+nw73QJBAMwBlq8N" +
            "iAbj/4ClszGkXa4ueCL1xglPjlWshao7/0F8bzKwdFpSnF07UAcaSuz1ht7ORMpc" +
            "a9vM0NxPlxFP80w=";

}
