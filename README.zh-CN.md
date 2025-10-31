# TLS 椭圆曲线加密

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![PHP Version Require](https://img.shields.io/packagist/php-v/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![License](https://img.shields.io/packagist/l/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![Build Status](https://img.shields.io/travis/tourze/tls-crypto-curves/master.svg?style=flat-square)](https://travis-ci.org/tourze/tls-crypto-curves)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-crypto-curves.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-crypto-curves)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/tourze/tls-crypto-curves/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-crypto-curves)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)

为 TLS 协议支持而设计的全面椭圆曲线加密库。该包提供了在 TLS 连接中常用的各种椭圆曲线的安全高效实现，包括 NIST 标准曲线和现代替代方案。

## 功能特性

- **NIST 标准曲线**: 完整支持 P-256、P-384 和 P-521 曲线
- **现代曲线**: 使用 Sodium 的 X25519 和 X448 曲线实现
- **安全密钥管理**: 加密安全的密钥对生成和公钥派生
- **OpenSSL 集成**: 原生 OpenSSL 扩展支持 NIST 曲线
- **类型安全**: 完整的 PHP 8.1+ 严格类型和全面的错误处理
- **性能优化**: 针对加密操作设计的高效实现
- **TLS 协议就绪**: 专为 TLS 握手和密钥交换设计

## 安装

### 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- Sodium 扩展（通过 paragonie/sodium_compat 自动提供）

### 通过 Composer 安装

```bash
composer require tourze/tls-crypto-curves
```

## 快速开始

### 使用 NIST P-256 的基本用法

```php
<?php

use Tourze\TLSCryptoCurves\NISTP256;

// 创建一个 P-256 曲线实例
$curve = new NISTP256();

// 生成一个安全的密钥对
$keyPair = $curve->generateKeyPair();
$privateKey = $keyPair['privateKey']; // PEM 格式
$publicKey = $keyPair['publicKey'];   // PEM 格式

// 从私钥派生公钥
$derivedPublicKey = $curve->derivePublicKey($privateKey);

// 显示曲线信息
echo "曲线名称: " . $curve->getName() . PHP_EOL;
echo "密钥大小: " . $curve->getKeySize() . " 位" . PHP_EOL;
```

### 现代 Curve25519 用法

```php
<?php

use Tourze\TLSCryptoCurves\Curve25519;

// 创建一个 Curve25519 实例
$curve = new Curve25519();

// 生成用于密钥交换的密钥对
$keyPair = $curve->generateKeyPair();
$privateKey = $keyPair['privateKey']; // 二进制格式
$publicKey = $keyPair['publicKey'];   // 二进制格式

// 从私钥派生公钥
$derivedPublicKey = $curve->derivePublicKey($privateKey);

echo "曲线名称: " . $curve->getName() . PHP_EOL;
echo "密钥大小: " . $curve->getKeySize() . " 位" . PHP_EOL;
```

### 使用不同的曲线

```php
<?php

use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;
use Tourze\TLSCryptoCurves\Curve448;

// P-384 曲线（更高安全性）
$p384 = new NISTP384();
$keyPair384 = $p384->generateKeyPair();

// P-521 曲线（最高安全性）
$p521 = new NISTP521();
$keyPair521 = $p521->generateKeyPair();

// Curve448（现代高安全性曲线）
$curve448 = new Curve448();
$keyPair448 = $curve448->generateKeyPair();
```

## 支持的曲线

| 曲线 | 类名 | 密钥大小 | 格式 | 安全级别 | 描述 |
|------|------|----------|------|-----------|------|
| P-256 | `NISTP256` | 256 位 | PEM | 标准 | NIST prime256v1，广泛支持 |
| P-384 | `NISTP384` | 384 位 | PEM | 高 | NIST secp384r1，增强安全性 |
| P-521 | `NISTP521` | 521 位 | PEM | 最高 | NIST secp521r1，最高安全性 |
| X25519 | `Curve25519` | 256 位 | 二进制 | 现代 | Curve25519 用于密钥交换 |
| X448 | `Curve448` | 448 位 | 二进制 | 高现代 | Curve448 用于高安全性应用 |

## 错误处理

所有曲线操作都通过 `CurveException` 类实现了全面的错误处理：

```php
<?php

use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\Exception\CurveException;

try {
    $curve = new NISTP256();
    $keyPair = $curve->generateKeyPair();
    
    // 执行加密操作
    $publicKey = $curve->derivePublicKey($keyPair['privateKey']);
    
} catch (CurveException $e) {
    echo "加密操作失败: " . $e->getMessage() . PHP_EOL;
    // 适当处理错误
}
```

## API 参考

### CurveInterface

所有曲线实现都遵循 `CurveInterface` 接口：

```php
interface CurveInterface
{
    public function getName(): string;
    public function getKeySize(): int;
    public function generateKeyPair(): array;
    public function derivePublicKey(string $privateKey): string;
}
```

### 可用方法

- `getName()`: 返回曲线标识符字符串
- `getKeySize()`: 返回密钥大小（位）
- `generateKeyPair()`: 生成安全密钥对
- `derivePublicKey(string $privateKey)`: 从私钥派生公钥

## 安全考虑

### 密钥管理
- 始终安全处理私钥，永远不要记录它们
- 根据您的安全要求使用适当的曲线
- 在生产环境中定期重新生成密钥

### 实现安全性
- NIST 曲线使用 OpenSSL 的加密安全随机数生成
- 现代曲线（X25519、X448）使用 Sodium 的安全实现
- 所有操作都包含适当的输入验证和错误处理

### 最佳实践
- 在进行加密操作之前验证所有输入参数
- 尽可能使用常量时间操作
- 遵循您组织的密钥管理政策

## 性能考虑

- NIST 曲线利用 OpenSSL 的优化实现
- 现代曲线受益于 Sodium 的高性能加密
- 密钥生成计算开销较大 - 在适当时进行缓存
- 公钥派生比密钥对生成更快

## 贡献

请参阅 [CONTRIBUTING.md](../../CONTRIBUTING.md) 了解我们的行为准则和提交拉取请求的过程。

## 许可证

MIT 许可证 (MIT)。详情请参阅 [许可证文件](LICENSE)。