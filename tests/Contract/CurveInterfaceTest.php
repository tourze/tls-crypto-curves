<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests\Contract;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\Exception\CurveException;
use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;

/**
 * CurveInterface 接口测试
 *
 * @internal
 */
#[CoversClass(CurveInterface::class)]
final class CurveInterfaceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        if (!extension_loaded('openssl')) {
            throw new CurveException('OpenSSL 扩展是运行此测试必需的');
        }
    }

    /**
     * 测试所有曲线实现类都实现了CurveInterface接口
     */
    public function testAllCurveImplementationsImplementInterface(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $this->assertInstanceOf(CurveInterface::class, $implementation);
        }
    }

    /**
     * 测试所有实现类都有getName方法并返回字符串
     */
    public function testAllImplementationsHaveGetNameMethod(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $this->assertNotEmpty($implementation->getName());
        }
    }

    /**
     * 测试所有实现类都有getKeySize方法并返回正整数
     */
    public function testAllImplementationsHaveGetKeySizeMethod(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $keySize = $implementation->getKeySize();
            $this->assertGreaterThan(0, $keySize);
        }
    }

    /**
     * 测试所有支持的实现类都能成功调用generateKeyPair方法
     */
    public function testAllImplementationsCanGenerateKeyPairs(): void
    {
        $implementations = [
            'Curve25519' => new Curve25519(),
            'Curve448' => new Curve448(),
            'NISTP256' => new NISTP256(),
            'NISTP384' => new NISTP384(),
            'NISTP521' => new NISTP521(),
        ];

        $supportedCount = 0;
        foreach ($implementations as $name => $implementation) {
            try {
                $keyPair = $implementation->generateKeyPair();
                $this->assertArrayHasKey('privateKey', $keyPair);
                $this->assertArrayHasKey('publicKey', $keyPair);
                ++$supportedCount;
            } catch (CurveException $e) {
                // 某些曲线可能在当前环境下不支持，继续测试其他曲线
                // 验证异常消息包含曲线名称，确保错误处理正确
                $this->assertStringContainsString($name, $e->getMessage(), "Exception should mention the curve name {$name}");
            }
        }

        // 至少要有一个曲线是支持的
        $this->assertGreaterThan(0, $supportedCount, '至少应该有一个椭圆曲线实现是支持的');
    }

    /**
     * 测试所有支持的实现类都能成功调用derivePublicKey方法
     */
    public function testAllImplementationsCanDerivePublicKeys(): void
    {
        $implementations = [
            'Curve25519' => new Curve25519(),
            'Curve448' => new Curve448(),
            'NISTP256' => new NISTP256(),
            'NISTP384' => new NISTP384(),
            'NISTP521' => new NISTP521(),
        ];

        $supportedCount = 0;
        foreach ($implementations as $name => $implementation) {
            try {
                $keyPair = $implementation->generateKeyPair();
                $derivedPublicKey = $implementation->derivePublicKey($keyPair['privateKey']);
                $this->assertNotEmpty($derivedPublicKey);
                ++$supportedCount;
            } catch (CurveException $e) {
                // 某些曲线可能在当前环境下不支持，继续测试其他曲线
                // 验证异常消息包含曲线名称，确保错误处理正确
                $this->assertStringContainsString($name, $e->getMessage(), "Exception should mention the curve name {$name}");
            }
        }

        // 至少要有一个曲线是支持的
        $this->assertGreaterThan(0, $supportedCount, '至少应该有一个椭圆曲线实现是支持的');
    }

    /**
     * 测试曲线名称的唯一性
     */
    public function testCurveNamesAreUnique(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        $names = [];
        foreach ($implementations as $implementation) {
            $name = $implementation->getName();
            $this->assertNotContains($name, $names, "Curve name '{$name}' is not unique");
            $names[] = $name;
        }
    }

    /**
     * 测试密钥大小的合理性
     */
    public function testKeySizesAreReasonable(): void
    {
        $curve25519 = new Curve25519();
        $this->assertEquals(256, $curve25519->getKeySize());

        $curve448 = new Curve448();
        $this->assertEquals(448, $curve448->getKeySize());

        $nistp256 = new NISTP256();
        $this->assertEquals(256, $nistp256->getKeySize());

        $nistp384 = new NISTP384();
        $this->assertEquals(384, $nistp384->getKeySize());

        $nistp521 = new NISTP521();
        $this->assertEquals(521, $nistp521->getKeySize());
    }
}
