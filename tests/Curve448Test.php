<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\Exception\CurveException;

/**
 * Curve448 椭圆曲线测试
 *
 * @internal
 */
#[CoversClass(Curve448::class)]
final class Curve448Test extends TestCase
{
    private Curve448 $curve;

    protected function setUp(): void
    {
        parent::setUp();

        $this->curve = new Curve448();
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
        $this->assertEquals('curve448', $this->curve->getName());
    }

    /**
     * 测试获取密钥大小
     */
    public function testGetKeySizeReturnsExpectedValue(): void
    {
        $this->assertEquals(448, $this->curve->getKeySize());
    }

    /**
     * 测试生成密钥对抛出不支持异常
     */
    public function testGenerateKeyPairThrowsUnsupportedException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');

        $this->curve->generateKeyPair();
    }

    /**
     * 测试派生公钥抛出不支持异常
     */
    public function testDerivePublicKeyThrowsUnsupportedException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');

        $this->curve->derivePublicKey('any-private-key-data');
    }

    /**
     * 测试用空字符串派生公钥抛出不支持异常
     */
    public function testDerivePublicKeyWithEmptyStringThrowsUnsupportedException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');

        $this->curve->derivePublicKey('');
    }

    /**
     * 测试用任意数据派生公钥都抛出不支持异常
     */
    public function testDerivePublicKeyWithAnyDataThrowsUnsupportedException(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('当前PHP环境不支持Curve448曲线');

        $this->curve->derivePublicKey(str_repeat('x', 56));
    }

    /**
     * 测试异常消息包含正确的曲线名称
     */
    public function testExceptionMessageContainsCurveName(): void
    {
        try {
            $this->curve->generateKeyPair();
            self::fail('Expected CurveException was not thrown');
        } catch (CurveException $e) {
            $this->assertStringContainsString('Curve448', $e->getMessage());
        }
    }

    /**
     * 测试派生公钥异常消息包含正确的曲线名称
     */
    public function testDerivePublicKeyExceptionMessageContainsCurveName(): void
    {
        try {
            $this->curve->derivePublicKey('test');
            self::fail('Expected CurveException was not thrown');
        } catch (CurveException $e) {
            $this->assertStringContainsString('Curve448', $e->getMessage());
        }
    }
}
