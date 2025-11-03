<?php

namespace EW\WaEncryptionTests;

use EW\WaEncryption\WhatsAppDecryptStreamDecorator;
use EW\WaEncryption\WhatsAppStreamDecorator;
use GuzzleHttp\Psr7\LazyOpenStream;
use PHPUnit\Framework\TestCase;

final class WhatsAppDecryptStreamDecoratorTest extends TestCase
{
    /**
     * @dataProvider fileMediaType
     */
    public function testDecoderGetContents(string $filename, string $mediaType): void
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

    public static function fileMediaType(): array
    {
        return [
            ['AUDIO', WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO],
            ['VIDEO', WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO],
            ['IMAGE', WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE],
        ];
    }

    /**
     * @dataProvider readLengths
     */
    public function testDecoderRead(int $len): void
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
            $chunk = $decoder->read($len);
            $content .= $chunk;
        }

        $this->assertEquals($content, $origContent);
    }

    public static function readLengths(): array
    {
        return array_fill(0, 5,
            [1, 8, 16, 50, 1024, 1024 * 1024]
        );
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

    public function testDecoderTell(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $decoder->read(1000);

        $this->assertEquals(1000, $decoder->tell());
    }

    public function testDecoderEof(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.encrypted", 'r');
        $decoder = new WhatsAppDecryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $decoder->getContents();

        $this->assertEquals(true, $decoder->eof());
    }

    public function testDecoderToString(): void
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

        $this->assertEquals($origContent, $decoder);
    }

    public function testDecoderRewind(): void
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

        $this->assertEquals($origContent, $decoder->read(strlen($origContent)));
        $decoder->rewind();
        $this->assertEquals($origContent, $decoder->read(strlen($origContent)));
    }
}