<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Contract;

/**
 * 椭圆曲线接口
 */
interface CurveInterface
{
    /**
     * 获取曲线名称
     */
    public function getName(): string;

    /**
     * 获取曲线的密钥大小（位）
     */
    public function getKeySize(): int;

    /**
     * 生成密钥对
     *
     * @return array<string, string> 包含私钥和公钥的数组
     */
    public function generateKeyPair(): array;

    /**
     * 从私钥生成公钥
     *
     * @param string $privateKey 私钥
     *
     * @return string 公钥
     */
    public function derivePublicKey(string $privateKey): string;
}
