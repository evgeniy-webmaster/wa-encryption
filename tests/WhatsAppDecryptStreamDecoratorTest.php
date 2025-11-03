<?php

namespace EW\WaEncryptionTests;

use EW\WaEncryption\WhatsAppDecryptStreamDecorator;
use EW\WaEncryption\WhatsAppStreamDecorator;
use GuzzleHttp\Psr7\LazyOpenStream;
use PHPUnit\Framework\TestCase;

final class WhatsAppDecryptStreamDecoratorTest extends TestCase
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

        $content = '';

        while (!$decoder->eof()) {
            $chunk = $decoder->read(rand(1, 1024));
            $content .= $chunk;
        }

        $this->assertEquals($content, $origContent);
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