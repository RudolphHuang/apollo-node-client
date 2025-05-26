import { generateKeyPairSync, publicEncrypt, privateDecrypt, KeyLike, KeyPairKeyObjectResult } from 'crypto';

/**
 * RSA工具类
 * 最佳实践：在应用启动时将字符格式的密钥转换为实例并缓存。
 */
export class RSAUtil {
  private static readonly KEY_ALGORITHM: string = 'RSA'; // 密钥算法
  private static readonly KEY_SIZE: number = 1024; // 密钥长度（位）

  /**
   * 生成新的RSA密钥对
   * @returns 返回包含公钥和私钥的对象
   */
  // static genKeyPair(): KeyPairKeyObjectResult {
  //   const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  //     modulusLength: this.KEY_SIZE,
  //   });
  //   return {
  //     publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  //     privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  //   };
  // }

  /**
   * 生成RSA密钥对字符串
   * @returns 返回公钥和私钥的Base64字符串数组
   */
  // static genKeyPairStrings(): string[] {
  //   const { publicKey, privateKey } = this.genKeyPair();
  //   return [
  //     publicKey.toString(), // 公钥字符串
  //     privateKey.toString(), // 私钥字符串
  //   ];
  // }

  /**
   * 从X.509格式的公钥字符串获取公钥对象
   * @param publicKey 公钥字符串（Base64格式）
   * @returns 返回PublicKey对象
   */
  static getPublicKeyFromX509(publicKey: string): KeyLike {
    return Buffer.from(publicKey, 'base64');
  }

  /**
   * 从PKCS#8格式的私钥字符串获取私钥对象
   * @param privateKey 私钥字符串（Base64格式）
   * @returns 返回PrivateKey对象
   */
  static getPrivateKeyFromPKCS8(privateKey: string): KeyLike {
    return Buffer.from(privateKey, 'base64');
  }

  /**
   * 使用公钥加密字符串
   * @param publicKey 公钥（PEM格式）
   * @param content 要加密的内容
   * @returns 返回加密后的内容（Base64编码字符串）
   */
  static encryptToBase64(publicKey: string, content: string): string {
    const buffer = Buffer.from(content, 'utf-8');
    const encrypted = publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
  }

  /**
   * 使用私钥解密Base64编码的字符串
   * @param privateKey 私钥（PEM格式）
   * @param content 加密的内容（Base64格式）
   * @returns 返回解密后的内容（字符串）
   */
  static decryptFromBase64(privateKey: string, content: string): string {
    const encryptedBuffer = Buffer.from(content, 'base64');
    const decrypted = privateDecrypt(privateKey, encryptedBuffer);
    return decrypted.toString('utf-8');
  }

  /**
   * 解密字节数据
   * @param privateKey 私钥（PEM格式）
   * @param encryptedData 加密后的字节数据
   * @returns 返回解密后的字符串
   */
  static decrypt(privateKey: string, encryptedData: Buffer): string {
    const decrypted = privateDecrypt(privateKey, encryptedData);
    return decrypted.toString('utf-8');
  }
}