<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Exception\CurveException;

/**
 * Curve25519 椭圆曲线测试
 *
 * @internal
 */
#[CoversClass(Curve25519::class)]
final class Curve25519Test extends TestCase
{
    private Curve25519 $curve;

    protected function setUp(): void
    {
        parent::setUp();

        $this->curve = new Curve25519();
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
        $this->assertEquals('curve25519', $this->curve->getName());
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
     * 测试生成的密钥对具有正确的长度
     */
    public function testGenerateKeyPairReturnsCorrectLengths(): void
    {
        $keyPair = $this->curve->generateKeyPair();

        // X25519密钥长度应该都是32字节
        $this->assertEquals(32, strlen($keyPair['privateKey']));
        $this->assertEquals(32, strlen($keyPair['publicKey']));
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

        $this->assertEquals($keyPair['publicKey'], $derivedPublicKey);
        $this->assertEquals(32, strlen($derivedPublicKey));
    }

    /**
     * 测试使用无效私钥派生公钥抛出异常
     */
    public function testDerivePublicKeyWithInvalidLengthThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');

        $this->curve->derivePublicKey('invalid-key-data');
    }

    /**
     * 测试使用空字符串派生公钥抛出异常
     */
    public function testDerivePublicKeyWithEmptyStringThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');

        $this->curve->derivePublicKey('');
    }

    /**
     * 测试使用错误长度的数据派生公钥抛出异常
     */
    public function testDerivePublicKeyWithWrongLengthThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');

        // 使用31字节的数据（应该是32字节）
        $this->curve->derivePublicKey(str_repeat('a', 31));
    }

    /**
     * 测试使用33字节的数据派生公钥抛出异常
     */
    public function testDerivePublicKeyWithTooLongKeyThrowsException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');

        // 使用33字节的数据
        $this->curve->derivePublicKey(str_repeat('a', 33));
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
}
