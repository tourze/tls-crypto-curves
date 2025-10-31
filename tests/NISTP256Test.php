<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Exception\CurveException;
use Tourze\TLSCryptoCurves\NISTP256;

/**
 * NIST P-256 椭圆曲线测试
 *
 * @internal
 */
#[CoversClass(NISTP256::class)]
final class NISTP256Test extends TestCase
{
    private NISTP256 $curve;

    protected function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('openssl')) {
            throw new CurveException('OpenSSL 扩展是运行此测试必需的');
        }

        $this->curve = new NISTP256();
    }

    /**
     * 测试实现CurveInterface接口
     */
    public function testImplementsCurveInterface(): void
    {
        $this->assertInstanceOf(CurveInterface::class, $this->curve);
    }

    /**
     * 测试获取曲线名称
     */
    public function testGetNameReturnsExpectedValue(): void
    {
        $this->assertEquals('nistp256', $this->curve->getName());
    }

    /**
     * 测试获取密钥大小
     */
    public function testGetKeySizeReturnsExpectedValue(): void
    {
        $this->assertEquals(256, $this->curve->getKeySize());
    }

    /**
     * 测试成功生成密钥对
     */
    public function testGenerateKeyPairSuccess(): void
    {
        $keyPair = $this->curve->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertIsString($keyPair['privateKey']);
        $this->assertIsString($keyPair['publicKey']);
    }

    /**
     * 测试生成的密钥对具有PEM格式
     */
    public function testGenerateKeyPairReturnsPemFormat(): void
    {
        $keyPair = $this->curve->generateKeyPair();

        // 检查PEM格式头部
        $this->assertStringContainsString('-----BEGIN', $keyPair['privateKey']);
        $this->assertStringContainsString('-----END', $keyPair['privateKey']);
        $this->assertStringContainsString('-----BEGIN', $keyPair['publicKey']);
        $this->assertStringContainsString('-----END', $keyPair['publicKey']);
    }

    /**
     * 测试生成的密钥对是有效的EC密钥
     */
    public function testGenerateKeyPairReturnsValidEcKeys(): void
    {
        $keyPair = $this->curve->generateKeyPair();

        // 验证私钥
        $privateKey = openssl_pkey_get_private($keyPair['privateKey']);
        $this->assertNotFalse($privateKey, 'Failed to load private key: ' . openssl_error_string());

        $privateKeyDetails = openssl_pkey_get_details($privateKey);
        $this->assertNotFalse($privateKeyDetails, 'Failed to get private key details: ' . openssl_error_string());
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $privateKeyDetails['type']);
        $this->assertEquals('prime256v1', $privateKeyDetails['ec']['curve_name']);

        // 验证公钥
        $publicKey = openssl_pkey_get_public($keyPair['publicKey']);
        $this->assertNotFalse($publicKey, 'Failed to load public key: ' . openssl_error_string());

        $publicKeyDetails = openssl_pkey_get_details($publicKey);
        $this->assertNotFalse($publicKeyDetails, 'Failed to get public key details: ' . openssl_error_string());
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $publicKeyDetails['type']);
        $this->assertEquals('prime256v1', $publicKeyDetails['ec']['curve_name']);
    }

    /**
     * 测试生成的密钥对每次都不同
     */
    public function testGenerateKeyPairReturnsDifferentKeys(): void
    {
        $keyPair1 = $this->curve->generateKeyPair();
        $keyPair2 = $this->curve->generateKeyPair();

        $this->assertNotEquals($keyPair1['privateKey'], $keyPair2['privateKey']);
        $this->assertNotEquals($keyPair1['publicKey'], $keyPair2['publicKey']);
    }

    /**
     * 测试从私钥成功派生公钥
     */
    public function testDerivePublicKeySuccess(): void
    {
        $keyPair = $this->curve->generateKeyPair();
        $derivedPublicKey = $this->curve->derivePublicKey($keyPair['privateKey']);

        $this->assertStringContainsString('-----BEGIN', $derivedPublicKey);
        $this->assertStringContainsString('-----END', $derivedPublicKey);

        // 验证派生的公钥是有效的
        $publicKey = openssl_pkey_get_public($derivedPublicKey);
        $this->assertNotFalse($publicKey, 'Failed to load derived public key: ' . openssl_error_string());

        $details = openssl_pkey_get_details($publicKey);
        $this->assertNotFalse($details, 'Failed to get derived public key details: ' . openssl_error_string());
        $this->assertEquals(OPENSSL_KEYTYPE_EC, $details['type']);
        $this->assertEquals('prime256v1', $details['ec']['curve_name']);
    }

    /**
     * 测试使用无效私钥派生公钥抛出异常
     */
    public function testDerivePublicKeyWithInvalidKeyThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('加载EC私钥失败');

        $this->curve->derivePublicKey('invalid-key-data');
    }

    /**
     * 测试使用空字符串派生公钥抛出异常
     */
    public function testDerivePublicKeyWithEmptyStringThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('加载EC私钥失败');

        $this->curve->derivePublicKey('');
    }

    /**
     * 测试使用错误格式的PEM数据派生公钥抛出异常
     */
    public function testDerivePublicKeyWithMalformedPemThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('加载EC私钥失败');

        $this->curve->derivePublicKey('-----BEGIN PRIVATE KEY-----invalid-----END PRIVATE KEY-----');
    }

    /**
     * 测试多次派生相同公钥的一致性
     */
    public function testDerivePublicKeyConsistency(): void
    {
        $keyPair = $this->curve->generateKeyPair();
        $privateKey = $keyPair['privateKey'];

        $publicKey1 = $this->curve->derivePublicKey($privateKey);
        $publicKey2 = $this->curve->derivePublicKey($privateKey);

        $this->assertEquals($publicKey1, $publicKey2);
    }

    /**
     * 测试派生的公钥与生成的公钥匹配
     */
    public function testDerivedPublicKeyMatchesGenerated(): void
    {
        $keyPair = $this->curve->generateKeyPair();
        $derivedPublicKey = $this->curve->derivePublicKey($keyPair['privateKey']);

        // 比较公钥的内容（去除格式差异）
        $originalKey = openssl_pkey_get_public($keyPair['publicKey']);
        $this->assertNotFalse($originalKey, 'Failed to load original public key: ' . openssl_error_string());

        $derivedKey = openssl_pkey_get_public($derivedPublicKey);
        $this->assertNotFalse($derivedKey, 'Failed to load derived public key: ' . openssl_error_string());

        $originalDetails = openssl_pkey_get_details($originalKey);
        $this->assertNotFalse($originalDetails, 'Failed to get original key details: ' . openssl_error_string());

        $derivedDetails = openssl_pkey_get_details($derivedKey);
        $this->assertNotFalse($derivedDetails, 'Failed to get derived key details: ' . openssl_error_string());

        $this->assertEquals($originalDetails['key'], $derivedDetails['key']);
    }
}
