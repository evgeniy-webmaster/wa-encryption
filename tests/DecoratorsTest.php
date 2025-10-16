<?php

declare(strict_types=1);

namespace EW\WaEncryptionTests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\LazyOpenStream;
use EW\WaEncryption\WhatsAppStreamDecorator;
use EW\WaEncryption\WhatsAppEncryptStreamDecorator;
use EW\WaEncryption\WhatsAppDecryptStreamDecorator;

final class DecoratorsTest extends TestCase
{
    /**
     * @dataProvider dataProvider
     */
    public function testDecoder($filename, $mediaType): void
    {
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );
        $this->assertEquals($decoder->getContents(), file_get_contents(__DIR__ . "/samples/$filename.original"));
    }

    /**
     * @dataProvider dataProvider
     */
    public function testEncoder($filename, $mediaType): void
    {
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $decoder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );
        $this->assertEquals($decoder->getContents(), file_get_contents(__DIR__ . "/samples/$filename.encrypted"));
    }

    public static function dataProvider(): array
    {
        return [
            ['AUDIO', WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO],
            ['VIDEO', WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO],
            ['IMAGE', WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE],
        ];
    }

    /*
    public function testSignature()
    {
        $filename = 'AUDIO';
        $mediaKeyExpanded = hash_hkdf(
            'sha256',
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            112,
            'WhatsApp Audio Keys'
        );

        $iv = substr($mediaKeyExpanded, 0, 16);
        $cipherKey = substr($mediaKeyExpanded, 16, 48 - 16);
        $macKey = substr($mediaKeyExpanded, 48, 80 - 48);

        $content = file_get_contents(__DIR__ . "/samples/$filename.encrypted");

        $file = substr($content, 0, strlen($content) - 10);
        $mac = substr($content, -10);

        $sign = hash_hmac(
            'sha256',
            $iv . $file,
            $macKey,
            true
        );

        $this->assertTrue(hash_equals(substr($sign, 0, 10), $mac));

        $decryptedContent = openssl_decrypt(
            $file,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA,
            $iv,
        );

        $this->assertEquals($decryptedContent, file_get_contents(__DIR__ . "/samples/$filename.original"));
    }
    */
}