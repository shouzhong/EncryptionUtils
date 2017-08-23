# EncryptionUtils
## 说明
加密工具类，这里收集了一些常用的加密方法，包括AES，DES，3DES，MD5，RSA，SHA1，SHA256，SHA384，SHA512。
## 使用
### 依赖
```
compile 'com.wuyifeng:EncryptionUtils:1.0.1'
```
### 使用说明
以下所有方法都为静态方法。
#### AESUtils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | AES加密后转为Base64编码</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | AES加密后转为16进制</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key | AES加密</br>@param data 明文</br>@param key  16、24、32字节秘钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | AES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  16、24、32字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | AES解密16进制密文</br>@param data 16进制密文</br>@param key  16、24、32字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | AES解密</br>@param data 密文</br>@param key  16、24、32字节秘钥</br>@return 明文
#### DES3Utils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | 3DES加密后转为Base64编码</br>@param data 明文</br>@param key  24字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | 3DES加密后转为16进制</br>@param data 明文</br>@param key  24字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key) | 3DES加密</br>@param data 明文</br>@param key  24字节密钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | 3DES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  24字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | 3DES解密16进制密文</br>@param data 16进制密文</br>@param key  24字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | 3DES解密</br>@param data 密文</br>@param key  24字节密钥</br>@return 明文
#### DESUtils
方法名 | 说明
------------ | -------------
byte[] encrypt2Base64(final byte[] data, final byte[] key) | DES加密后转为Base64编码</br>@param data 明文</br>@param key  8字节秘钥</br>@return Base64密文
String encrypt2HexString(final byte[] data, final byte[] key) | DES加密后转为16进制</br>@param data 明文</br>@param key  8字节秘钥</br>@return 16进制密文
byte[] encrypt(final byte[] data, final byte[] key) | DES加密</br>@param data 明文</br>@param key  8字节密钥</br>@return 密文
byte[] decryptBase64(final byte[] data, final byte[] key) | DES解密Base64编码密文</br>@param data Base64编码密文</br>@param key  8字节秘钥</br>@return 明文
byte[] decryptHexString(final String data, final byte[] key) | DES解密16进制密文</br>@param data 16进制密文</br>@param key  8字节秘钥</br>@return 明文
byte[] decrypt(final byte[] data, final byte[] key) | DES解密</br>@param data 密文</br>@param key  8字节密钥</br>@return 明文
#### MD5Utils
方法名 | 说明
------------ | -------------
String encrypt2String(final String data, final String salt) | MD5加密</br>@param data 明文字符串</br>@param salt 盐</br>@return 16进制加盐密文
String encrypt2String(final byte[] data) | MD5加密</br>@param data 明文字节数组</br>@return 16进制密文
String encrypt2String(final byte[] data, final byte[] salt) | MD5加密</br>@param data 明文字节数组</br>@param salt 盐字节数组</br>@return 16进制加盐密文
byte[] encrypt(final byte[] data) | MD5加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptFile2String(final String filePath) | MD5加密文件</br>@param filePath 文件路径</br>@return 文件的16进制密文
byte[] encryptFile(final String filePath) | MD5加密文件</br>@param filePath 文件路径</br>@return 文件的MD5校验码
String encryptFile2String(final File file) | MD5加密文件</br>@param file 文件</br>@return 文件的16进制密文
byte[] encryptFile(final File file) | MD5加密文件</br>@param file 文件</br>@return 文件的MD5校验码
String encryptHmac2String(final String data, final String key) | HmacMD5加密</br>@param data 明文字符串</br>@param key 秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacMD5加密</br>@param data 明文字节数组</br>@param key 秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacMD5加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
#### RSAUtils
方法名 | 说明
------------ | -------------
密钥
KeyPair generateRSAKeyPair(int keyLength) | 随机生成RSA密钥对</br>@param keyLength 密钥长度，范围：512～2048 一般1024</br>@return 密钥对
PrivateKey getPrivateKey(String privateKey) | 获取私钥</br>@param privateKey 私钥字符串</br>@return 私钥
PrivateKey getPrivateKey(byte[] privateKey) | 获取私钥</br>@param privateKey 私钥数据</br>@return 私钥
PublicKey getPublicKey(String publicKey) | 获取公钥</br>@param publicKey 公钥字符串</br>@return 公钥
PublicKey getPublicKey(byte[] publicKey) | 获取公钥</br>@param publicKey 公钥数据</br>@return 公钥
私钥解密
String decryptBase64ToStringFromNetByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param privateKey 私钥字符串</br>@param encrypted 加密的数据</br>@return 解密后的字符串
String decryptBase64ToStringFromNetByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param privateKey 私钥</br>@param encrypted 加密的数据</br>@return 解密后的字符串
byte[] decryptBase64FromNetByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param privateKey 私钥</br>@param encrypted 加密的数据</br>@return 解密后的数据
byte[] decryptBase64FromNetByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param privateKey 私钥</br>@param encrypted 加密的数据</br>@return 解密后的数据
String decryptBase64ToStringByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过的base64数据</br>@param privateKey 私钥字符串</br>@param encrypted 加密的字符串</br>@return 解密后的字符串
String decryptBase64ToStringByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过的base64数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的字符串
byte[] decryptBase64ByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过的base64数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的数据
byte[] decryptBase64ByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过的base64数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的数据</br>@throws Exception 异常
String decryptHex2StringByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过的16进制数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的字符串
String decryptHex2StringByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过的16进制数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的字符串
byte[] decryptHexByPrivateKey(String privateKey, String encrypted) | 解密RSA公钥加密过的16进制数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的数据
byte[] decryptHexByPrivateKey(PrivateKey privateKey, String encrypted) | 解密RSA公钥加密过的16进制数据</br>@param privateKey 私钥</br>@param encrypted 加密的字符串</br>@return 解密后的数据
String decrypt2StringByPrivateKey(String privateKey, byte[] encryptedData) | 解密RSA公钥加密过的数据</br>@param privateKey 私钥字符串</br>@param encryptedData 加密的数据</br>@return 解密后的字符串
String decrypt2StringByPrivateKey(PrivateKey privateKey, byte[] encryptedData) | 解密RSA公钥加密过的字符串</br>@param privateKey 私钥字符串</br>@param encryptedData 加密的数据</br>@return 解密后的数据
byte[] decryptByPrivateKey(String privateKey, byte[] encryptedData) | 解密RSA公钥加密过的数据</br>@param privateKey 私钥字符串</br>@param encryptedData 加密的数据</br>@return 解密后的数据
byte[] decryptByPrivateKey(PrivateKey privateKey, byte[] encryptedData) | 解密RSA公钥加密过的数据</br>@param privateKey 私钥</br>@param encryptedData 加密的数据</br>@return 解密后的数据
公钥解密
String decryptBase64ToStringFromNetByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥字符串</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
String decryptBase64ToStringFromNetByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
byte[] decryptBase64FromNetByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
byte[] decryptBase64FromNetByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过符合网络安全的base64数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
String decryptBase64ToStringByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过的base64数据</br>@param publicKey 公钥字符串</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
String decryptBase64ToStringByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过的base64数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
byte[] decryptBase64ByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过的base64数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
byte[] decryptBase64ByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过的base64数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
String decryptHex2StringByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过的16进制数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
String decryptHex2StringByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过的16进制数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的字符串
byte[] decryptHexByPublicKey(String publicKey, String encryptedData) | 解密RSA私钥加密过的16进制数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
byte[] decryptHexByPublicKey(PublicKey publicKey, String encryptedData) | 解密RSA私钥加密过的16进制数据</br>@param publicKey 公钥</br>@param encryptedData 加密的字符串</br>@return 解密的数据
String decrypt2StringByPublicKey(String publicKey, byte[] encryptedData) | 解密RSA私钥加密过的数据</br>@param publicKey 公钥字符串</br>@param encryptedData 加密的数据</br>@return 解密的字符串
String decrypt2StringByPublicKey(PublicKey publicKey, byte[] encryptedData) | 解密RSA私钥加密过的数据</br>@param publicKey 公钥字符串</br>@param encryptedData 加密的数据</br>@return 解密的字符串
byte[] decryptByPublicKey(String publicKey, byte[] encryptedData) | 解密RSA私钥加密过的数据</br>@param publicKey 公钥字符串</br>@param encryptedData 加密的数据</br>@return 解密的数据
byte[] decryptByPublicKey(PublicKey publicKey, byte[] encryptedData) | 解密RSA私钥加密过的数据</br>@param publicKey 公钥</br>@param encryptedData 加密的数据</br>@return 解密的数据
私钥加密
String encryptBase64ToNetByPrivateKey(String privateKey, String data) | 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""</br>@param privateKey 私钥字符串</br>@param data 数据</br>@return 加密后符合网络安全的base64数据
String encryptBase64ToNetByPrivateKey(PrivateKey privateKey, String data) | 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""）</br>@param privateKey</br>@param data 数据</br>@return 加密后符合网络安全的base64数据
String encryptBase64ToNetByPrivateKey(String privateKey, byte[] data) | 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""）</br>@param privateKey</br>@param data 数据</br>@return 加密后符合网络安全的base64数据
String encryptBase64ToNetByPrivateKey(PrivateKey privateKey, byte[] data) | 私钥加密成符合网络安全的字符串（将"+"替换成"-"，"/"替换成"_","="替换成""）</br>@param privateKey</br>@param data 数据</br>@return 加密后符合网络安全的base64数据
String encryptBase64ByPrivateKey(String privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后base64的数据
String encryptBase64ByPrivateKey(PrivateKey privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后base64的数据
String encryptBase64ByPrivateKey(String privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后base64的数据
String encryptBase64ByPrivateKey(PrivateKey privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后base64的数据
String encryptHexByPrivateKey(String privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后的16进制数据
String encryptHexByPrivateKey(PrivateKey privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后的16进制数据
String encryptHexByPrivateKey(String privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后的16进制数据
String encryptHexByPrivateKey(PrivateKey privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后的16进制数据
byte[] encryptByPrivateKey(String privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥字符串</br>@param data 数据</br>@return 加密后的数据
byte[] encryptByPrivateKey(PrivateKey privateKey, String data) | 私钥加密数据</br>@param privateKey 私钥字符串</br>@param data 数据</br>@return 加密后的数据
byte[] encryptByPrivateKey(String privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥字符串</br>@param data 数据</br>@return 加密后的数据
byte[] encryptByPrivateKey(PrivateKey privateKey, byte[] data) | 私钥加密数据</br>@param privateKey 私钥</br>@param data 数据</br>@return 加密后的数据
公钥加密
String encryptBase64ToNetByPublicKey(String publicKey, String data) | 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥字符串</br>@param data 待加密的字符串</br>@return 加密后的符合网络安全的base64字符串
String encryptBase64ToNetByPublicKey(PublicKey publicKey, String data) | 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param data 待加密的字符串</br>@return 加密后的符合网络安全的base64字符串
String encryptBase64ToNetByPublicKey(String publicKey, byte[] data) | 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的符合网络安全的base64字符串
String encryptBase64ToNetByPublicKey(PublicKey publicKey, byte[] data) | 公钥加密成符合网络安全的数据(将"+"替换成"-"，"/"替换成"_","="替换成"")</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的符合网络安全的base64字符串
String encryptBase64ByPublicKey(String publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥字符串</br>@param data 待加密的字符串</br>@return 加密后的base64字符串
String encryptBase64ByPublicKey(PublicKey publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的字符串</br>@return 加密后的base64字符串
String encryptBase64ByPublicKey(String publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的base64字符串
String encryptBase64ByPublicKey(PublicKey publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的base64字符串
String encryptHexByPublicKey(String publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的16进制字符串
String encryptHexByPublicKey(PublicKey publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的16进制字符串
String encryptHexByPublicKey(String publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的16进制字符串
String encryptHexByPublicKey(PublicKey publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的16进制字符串
byte[] encryptByPublicKey(String publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥字符串</br>@param data 待加密的数据</br>@return 加密后的数据
byte[] encryptByPublicKey(PublicKey publicKey, String data) | 公钥加密数据</br>@param publicKey 公钥字符串</br>@param data 待加密的数据</br>@return 加密后的数据
byte[] encryptByPublicKey(String publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥字符串</br>@param data 待加密的数据</br>@return 加密后的数据
byte[] encryptByPublicKey(PublicKey publicKey, byte[] data) | 公钥加密数据</br>@param publicKey 公钥</br>@param data 待加密的数据</br>@return 加密后的数据
#### SHA1Utils
方法名 | 说明
------------ | -------------
String encrypt2String(final String data) | SHA1加密</br>@param data 明文字符串</br>@return 16进制密文
String encrypt2String(final byte[] data) | SHA1加密</br>@param data 明文字节数组</br>@return 16进制密文
byte[] encrypt(final byte[] data) | SHA1加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptHmac2String(final String data, final String key) | HmacSHA1加密</br>@param data 明文字符串</br>@param key  秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacSHA1加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacSHA1加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
#### SHA256Utils
方法名 | 说明
------------ | -------------
String encrypt2String(final String data) | SHA256加密</br>@param data 明文字符串</br>@return 16进制密文
String encrypt2String(final byte[] data) | SHA256加密</br>@param data 明文字节数组</br>@return 16进制密文
byte[] encrypt(final byte[] data) | SHA256加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptHmac2String(final String data, final String key) | HmacSHA256加密</br>@param data 明文字符串</br>@param key  秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacSHA256加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacSHA256加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
#### SHA384Utils
方法名 | 说明
------------ | -------------
String encrypt2String(final String data) | SHA384加密</br>@param data 明文字符串</br>@return 16进制密文
String encrypt2String(final byte[] data) | SHA384加密</br>@param data 明文字节数组</br>@return 16进制密文
byte[] encrypt(final byte[] data) | SHA384加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptHmac2String(final String data, final String key) | HmacSHA384加密</br>@param data 明文字符串</br>@param key  秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacSHA384加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacSHA384加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
#### SHA512Utils
------------ | -------------
String encrypt2String(final String data) | SHA512加密</br>@param data 明文字符串</br>@return 16进制密文
String encrypt2String(final byte[] data) | SHA512加密</br>@param data 明文字节数组</br>@return 16进制密文
byte[] encrypt(final byte[] data) | SHA512加密</br>@param data 明文字节数组</br>@return 密文字节数组
String encryptHmac2String(final String data, final String key) | HmacSHA512加密</br>@param data 明文字符串</br>@param key  秘钥</br>@return 16进制密文
String encryptHmac2String(final byte[] data, final byte[] key) | HmacSHA512加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 16进制密文
byte[] encryptHmac(final byte[] data, final byte[] key) | HmacSHA512加密</br>@param data 明文字节数组</br>@param key  秘钥</br>@return 密文字节数组
