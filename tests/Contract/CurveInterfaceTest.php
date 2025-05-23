<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Contract\CurveInterface;
use Tourze\TLSCryptoCurves\Curve25519;
use Tourze\TLSCryptoCurves\Curve448;
use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;

/**
 * CurveInterface 接口测试
 */
class CurveInterfaceTest extends TestCase
{
    /**
     * 测试所有曲线实现类都实现了CurveInterface接口
     */
    public function test_all_curve_implementations_implement_interface(): void
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
    public function test_all_implementations_have_get_name_method(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $this->assertIsString($implementation->getName());
            $this->assertNotEmpty($implementation->getName());
        }
    }

    /**
     * 测试所有实现类都有getKeySize方法并返回正整数
     */
    public function test_all_implementations_have_get_key_size_method(): void
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
            $this->assertIsInt($keySize);
            $this->assertGreaterThan(0, $keySize);
        }
    }

    /**
     * 测试所有实现类都有generateKeyPair方法
     */
    public function test_all_implementations_have_generate_key_pair_method(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $this->assertTrue(method_exists($implementation, 'generateKeyPair'));
        }
    }

    /**
     * 测试所有实现类都有derivePublicKey方法
     */
    public function test_all_implementations_have_derive_public_key_method(): void
    {
        $implementations = [
            new Curve25519(),
            new Curve448(),
            new NISTP256(),
            new NISTP384(),
            new NISTP521(),
        ];

        foreach ($implementations as $implementation) {
            $this->assertTrue(method_exists($implementation, 'derivePublicKey'));
        }
    }

    /**
     * 测试曲线名称的唯一性
     */
    public function test_curve_names_are_unique(): void
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
    public function test_key_sizes_are_reasonable(): void
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