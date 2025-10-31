# TLS Crypto Curves

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![PHP Version Require](https://img.shields.io/packagist/php-v/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![License](https://img.shields.io/packagist/l/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)
[![Build Status](https://img.shields.io/travis/tourze/tls-crypto-curves/master.svg?style=flat-square)](https://travis-ci.org/tourze/tls-crypto-curves)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-crypto-curves.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-crypto-curves)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/tourze/tls-crypto-curves/master.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/tls-crypto-curves)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-crypto-curves.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-crypto-curves)

A comprehensive elliptic curve cryptography library for TLS protocol support. This package provides secure implementations of various elliptic curves commonly used in TLS connections, including NIST standard curves and modern alternatives.

## Features

- **NIST Standard Curves**: Complete support for P-256, P-384, and P-521 curves
- **Modern Curves**: X25519 and X448 curve implementations using Sodium
- **Secure Key Management**: Cryptographically secure key pair generation and public key derivation
- **OpenSSL Integration**: Native OpenSSL extension support for NIST curves
- **Type Safety**: Full PHP 8.1+ strict typing with comprehensive error handling
- **Performance Optimized**: Efficient implementations designed for cryptographic operations
- **TLS Protocol Ready**: Designed specifically for TLS handshake and key exchange

## Installation

### Requirements

- PHP 8.1 or higher
- OpenSSL extension
- Sodium extension (automatically provided via paragonie/sodium_compat)

### Installation via Composer

```bash
composer require tourze/tls-crypto-curves
```

## Quick Start

### Basic Usage with NIST P-256

```php
<?php

use Tourze\TLSCryptoCurves\NISTP256;

// Create a P-256 curve instance
$curve = new NISTP256();

// Generate a secure key pair
$keyPair = $curve->generateKeyPair();
$privateKey = $keyPair['privateKey']; // PEM format
$publicKey = $keyPair['publicKey'];   // PEM format

// Derive public key from private key
$derivedPublicKey = $curve->derivePublicKey($privateKey);

// Display curve information
echo "Curve Name: " . $curve->getName() . PHP_EOL;
echo "Key Size: " . $curve->getKeySize() . " bits" . PHP_EOL;
```

### Modern Curve25519 Usage

```php
<?php

use Tourze\TLSCryptoCurves\Curve25519;

// Create a Curve25519 instance
$curve = new Curve25519();

// Generate a key pair for key exchange
$keyPair = $curve->generateKeyPair();
$privateKey = $keyPair['privateKey']; // Binary format
$publicKey = $keyPair['publicKey'];   // Binary format

// Derive public key from private key
$derivedPublicKey = $curve->derivePublicKey($privateKey);

echo "Curve Name: " . $curve->getName() . PHP_EOL;
echo "Key Size: " . $curve->getKeySize() . " bits" . PHP_EOL;
```

### Working with Different Curves

```php
<?php

use Tourze\TLSCryptoCurves\NISTP384;
use Tourze\TLSCryptoCurves\NISTP521;
use Tourze\TLSCryptoCurves\Curve448;

// P-384 curve (higher security)
$p384 = new NISTP384();
$keyPair384 = $p384->generateKeyPair();

// P-521 curve (maximum security)
$p521 = new NISTP521();
$keyPair521 = $p521->generateKeyPair();

// Curve448 (modern high-security curve)
$curve448 = new Curve448();
$keyPair448 = $curve448->generateKeyPair();
```

## Supported Curves

| Curve | Class | Key Size | Format | Security Level | Description |
|-------|-------|----------|--------|----------------|-------------|
| P-256 | `NISTP256` | 256 bits | PEM | Standard | NIST prime256v1, widely supported |
| P-384 | `NISTP384` | 384 bits | PEM | High | NIST secp384r1, enhanced security |
| P-521 | `NISTP521` | 521 bits | PEM | Maximum | NIST secp521r1, highest security |
| X25519 | `Curve25519` | 256 bits | Binary | Modern | Curve25519 for key exchange |
| X448 | `Curve448` | 448 bits | Binary | High Modern | Curve448 for high-security applications |

## Error Handling

All curve operations implement comprehensive error handling through the `CurveException` class:

```php
<?php

use Tourze\TLSCryptoCurves\NISTP256;
use Tourze\TLSCryptoCurves\Exception\CurveException;

try {
    $curve = new NISTP256();
    $keyPair = $curve->generateKeyPair();
    
    // Perform cryptographic operations
    $publicKey = $curve->derivePublicKey($keyPair['privateKey']);
    
} catch (CurveException $e) {
    echo "Cryptographic operation failed: " . $e->getMessage() . PHP_EOL;
    // Handle the error appropriately
}
```

## API Reference

### CurveInterface

All curve implementations follow the `CurveInterface`:

```php
interface CurveInterface
{
    public function getName(): string;
    public function getKeySize(): int;
    public function generateKeyPair(): array;
    public function derivePublicKey(string $privateKey): string;
}
```

### Available Methods

- `getName()`: Returns the curve identifier string
- `getKeySize()`: Returns the key size in bits
- `generateKeyPair()`: Generates a secure key pair
- `derivePublicKey(string $privateKey)`: Derives public key from private key

## Security Considerations

### Key Management
- Always handle private keys securely and never log them
- Use appropriate curves for your security requirements
- Regenerate keys periodically in production environments

### Implementation Security
- NIST curves use OpenSSL's cryptographically secure random number generation
- Modern curves (X25519, X448) use Sodium's secure implementations
- All operations include proper input validation and error handling

### Best Practices
- Validate all input parameters before cryptographic operations
- Use constant-time operations where possible
- Follow your organization's key management policies

## Performance Considerations

- NIST curves leverage OpenSSL's optimized implementations
- Modern curves benefit from Sodium's high-performance cryptography
- Key generation is computationally expensive - cache when appropriate
- Public key derivation is faster than key pair generation

## Contributing

Please see [CONTRIBUTING.md](../../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.