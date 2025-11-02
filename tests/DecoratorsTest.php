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
    public function testDecoderGetContents($filename, $mediaType): void
    {
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $origContent = file_get_contents(__DIR__ . "/samples/$filename.original");
        $content = $decoder->getContents();
        $this->assertEquals($content, $origContent);
    }


    public function testDecoderRead(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $origContent = file_get_contents(__DIR__ . "/samples/$filename.original");

        $lens = [1, 8, 16, 32, 1024, 1024 * 1024];

        foreach ($lens as $len) {
            $content = '';

            while (!$decoder->eof()) {
                $chunk = $decoder->read($len);
                $content .= $chunk;
            }

            $this->assertEquals($content, $origContent);
            $decoder->rewind();
        }
    }

    public function testDecoderReadRandLen(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $origContent = file_get_contents(__DIR__ . "/samples/$filename.original");

        while (!$decoder->eof()) {
            $chunk = $decoder->read(rand(1, 1024));
            $content .= $chunk;
        }

        $this->assertEquals($content, $origContent);
    }


    /**
     * @dataProvider dataProvider
     */
    public function testEncoder($filename, $mediaType): void
    {
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );
        $eContent = file_get_contents(__DIR__ . "/samples/$filename.encrypted");
        $content = $coder->getContents();

        $this->assertEquals($content, $eContent);
    }

    public function testEncoderRead(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $eContent = file_get_contents(__DIR__ . "/samples/$filename.encrypted");

        $lens = [1, 8, 16, 32, 1024, 1024 * 1024];

        foreach ($lens as $len) {
            $content = '';

            while (!$coder->eof()) {
                $chunk = $coder->read($len);
                $content .= $chunk;
            }

            $this->assertEquals($content, $eContent);
            $coder->rewind();
        }
    }

    public function testEncoderReadRandLen(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $eContent = file_get_contents(__DIR__ . "/samples/$filename.encrypted");

        while (!$coder->eof()) {
            $chunk = $coder->read(rand(1, 1024));
            $content .= $chunk;
        }

        $this->assertEquals($content, $eContent);
    }

    public static function dataProvider(): array
    {
        return [
            ['AUDIO', WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO],
            ['VIDEO', WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO],
            ['IMAGE', WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE],
        ];
    }
}