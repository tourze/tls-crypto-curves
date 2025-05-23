<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Exception\CurveException;

/**
 * Curve25519 椭圆曲线测试
 */
class Curve25519Test extends TestCase
{
    private Curve25519 $curve;

    protected function setUp(): void
    {
        $this->curve = new Curve25519();
    }

    /**
     * 测试实现CurveInterface接口
     */
    public function test_implements_curve_interface(): void
    {
        $this->assertInstanceOf(CurveInterface::class, $this->curve);
    }

    /**
     * 测试获取曲线名称
     */
    public function test_get_name_returns_expected_value(): void
    {
        $this->assertEquals('curve25519', $this->curve->getName());
    }

    /**
     * 测试获取密钥大小
     */
    public function test_get_key_size_returns_expected_value(): void
    {
        $this->assertEquals(256, $this->curve->getKeySize());
    }

    /**
     * 测试成功生成密钥对
     */
    public function test_generate_key_pair_success(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $keyPair = $this->curve->generateKeyPair();

        $this->assertArrayHasKey('privateKey', $keyPair);
        $this->assertArrayHasKey('publicKey', $keyPair);
        $this->assertIsString($keyPair['privateKey']);
        $this->assertIsString($keyPair['publicKey']);
    }

    /**
     * 测试生成的密钥对具有正确的长度
     */
    public function test_generate_key_pair_returns_correct_lengths(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $keyPair = $this->curve->generateKeyPair();

        // X25519密钥长度应该都是32字节
        $this->assertEquals(32, strlen($keyPair['privateKey']));
        $this->assertEquals(32, strlen($keyPair['publicKey']));
    }

    /**
     * 测试生成的密钥对每次都不同
     */
    public function test_generate_key_pair_returns_different_keys(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $keyPair1 = $this->curve->generateKeyPair();
        $keyPair2 = $this->curve->generateKeyPair();

        $this->assertNotEquals($keyPair1['privateKey'], $keyPair2['privateKey']);
        $this->assertNotEquals($keyPair1['publicKey'], $keyPair2['publicKey']);
    }

    /**
     * 测试从私钥成功派生公钥
     */
    public function test_derive_public_key_success(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $keyPair = $this->curve->generateKeyPair();
        $derivedPublicKey = $this->curve->derivePublicKey($keyPair['privateKey']);

        $this->assertEquals($keyPair['publicKey'], $derivedPublicKey);
        $this->assertEquals(32, strlen($derivedPublicKey));
    }

    /**
     * 测试使用无效私钥派生公钥抛出异常
     */
    public function test_derive_public_key_with_invalid_length_throws_exception(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');
        
        $this->curve->derivePublicKey('invalid-key-data');
    }

    /**
     * 测试使用空字符串派生公钥抛出异常
     */
    public function test_derive_public_key_with_empty_string_throws_exception(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');
        
        $this->curve->derivePublicKey('');
    }

    /**
     * 测试使用错误长度的数据派生公钥抛出异常
     */
    public function test_derive_public_key_with_wrong_length_throws_exception(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');
        
        // 使用31字节的数据（应该是32字节）
        $this->curve->derivePublicKey(str_repeat('a', 31));
    }

    /**
     * 测试使用33字节的数据派生公钥抛出异常
     */
    public function test_derive_public_key_with_too_long_key_throws_exception(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('无效的Curve25519私钥长度');
        
        // 使用33字节的数据
        $this->curve->derivePublicKey(str_repeat('a', 33));
    }

    /**
     * 测试多次派生相同公钥的一致性
     */
    public function test_derive_public_key_consistency(): void
    {
        if (!class_exists('ParagonIE_Sodium_Compat')) {
            $this->markTestSkipped('sodium_compat库不可用，无法测试Curve25519');
        }

        $keyPair = $this->curve->generateKeyPair();
        $privateKey = $keyPair['privateKey'];

        $publicKey1 = $this->curve->derivePublicKey($privateKey);
        $publicKey2 = $this->curve->derivePublicKey($privateKey);

        $this->assertEquals($publicKey1, $publicKey2);
    }
}
