<?php

declare(strict_types=1);

namespace Tourze\TLSCryptoCurves\Tests\Exception;

use PHPUnit\Framework\TestCase;
use Tourze\TLSCryptoCurves\Exception\CurveException;

/**
 * CurveException 异常类测试
 */
class CurveExceptionTest extends TestCase
{
    /**
     * 测试异常继承自Exception
     */
    public function test_extends_exception(): void
    {
        $exception = new CurveException('Test message');
        $this->assertInstanceOf(\Exception::class, $exception);
    }

    /**
     * 测试异常消息设置
     */
    public function test_exception_message(): void
    {
        $message = 'Test curve exception message';
        $exception = new CurveException($message);
        
        $this->assertEquals($message, $exception->getMessage());
    }

    /**
     * 测试异常代码设置
     */
    public function test_exception_code(): void
    {
        $code = 500;
        $exception = new CurveException('Test message', $code);
        
        $this->assertEquals($code, $exception->getCode());
    }

    /**
     * 测试异常前一个异常设置
     */
    public function test_exception_previous(): void
    {
        $previous = new \RuntimeException('Previous exception');
        $exception = new CurveException('Test message', 0, $previous);
        
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试空消息异常
     */
    public function test_empty_message_exception(): void
    {
        $exception = new CurveException('');
        
        $this->assertEquals('', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试默认参数异常
     */
    public function test_default_parameters(): void
    {
        $exception = new CurveException('Test message');
        
        $this->assertEquals('Test message', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试异常可以被抛出和捕获
     */
    public function test_can_be_thrown_and_caught(): void
    {
        $this->expectException(CurveException::class);
        $this->expectExceptionMessage('Test throwable exception');
        
        throw new CurveException('Test throwable exception');
    }

    /**
     * 测试异常类型检查
     */
    public function test_instanceof_checks(): void
    {
        $exception = new CurveException('Test message');
        
        $this->assertInstanceOf(CurveException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertInstanceOf(\Throwable::class, $exception);
    }

    /**
     * 测试异常字符串表示
     */
    public function test_string_representation(): void
    {
        $exception = new CurveException('Test message', 123);
        $string = (string) $exception;
        
        $this->assertStringContainsString('CurveException', $string);
        $this->assertStringContainsString('Test message', $string);
    }
} 