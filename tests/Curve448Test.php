<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\Exception\CurveException;

/**
 * Curve448 椭圆曲线测试
 */
class Curve448Test extends TestCase
{
    private Curve448 $curve;

    protected function setUp(): void
    {
        $this->curve = new Curve448();
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
        $this->assertEquals('curve448', $this->curve->getName());
    }

    /**
     * 测试获取密钥大小
     */
    public function test_get_key_size_returns_expected_value(): void
    {
        $this->assertEquals(448, $this->curve->getKeySize());
    }

    /**
     * 测试生成密钥对抛出不支持异常
     */
    public function test_generate_key_pair_throws_unsupported_exception(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');
        
        $this->curve->generateKeyPair();
    }

    /**
     * 测试派生公钥抛出不支持异常
     */
    public function test_derive_public_key_throws_unsupported_exception(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');
        
        $this->curve->derivePublicKey('any-private-key-data');
    }

    /**
     * 测试用空字符串派生公钥抛出不支持异常
     */
    public function test_derive_public_key_with_empty_string_throws_unsupported_exception(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');
        
        $this->curve->derivePublicKey('');
    }

    /**
     * 测试用任意数据派生公钥都抛出不支持异常
     */
    public function test_derive_public_key_with_any_data_throws_unsupported_exception(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');
        
        $this->curve->derivePublicKey(str_repeat('x', 56));
    }

    /**
     * 测试异常消息包含正确的曲线名称
     */
    public function test_exception_message_contains_curve_name(): void
    {
        try {
            $this->curve->generateKeyPair();
            $this->fail('Expected CurveException was not thrown');
        } catch (CurveException $e) {
            $this->assertStringContainsString('Curve448', $e->getMessage());
        }
    }

    /**
     * 测试派生公钥异常消息包含正确的曲线名称
     */
    public function test_derive_public_key_exception_message_contains_curve_name(): void
    {
        try {
            $this->curve->derivePublicKey('test');
            $this->fail('Expected CurveException was not thrown');
        } catch (CurveException $e) {
            $this->assertStringContainsString('Curve448', $e->getMessage());
        }
    }
} 