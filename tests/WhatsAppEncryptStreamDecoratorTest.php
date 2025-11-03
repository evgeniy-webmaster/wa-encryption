<?php

declare(strict_types=1);

namespace EW\WaEncryptionTests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\LazyOpenStream;
use EW\WaEncryption\WhatsAppStreamDecorator;
use EW\WaEncryption\WhatsAppEncryptStreamDecorator;
use EW\WaEncryption\WhatsAppDecryptStreamDecorator;

final class WhatsAppEncryptStreamDecoratorTest extends TestCase
{
    /**
     * @dataProvider fileMediaType
     */
    public function testEncoder(string $filename, string $mediaType): void
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

    /**
     * @dataProvider readLengths
     */
    public function testEncoderRead(int $len): void
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


        $content = '';

        while (!$coder->eof()) {
            $chunk = $coder->read($len);
            $content .= $chunk;
        }

        $this->assertEquals($content, $eContent);
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

        $content = '';

        while (!$coder->eof()) {
            $chunk = $coder->read(rand(1, 1024));
            $content .= $chunk;
        }

        $this->assertEquals($content, $eContent);
    }

    public static function fileMediaType(): array
    {
        return [
            ['AUDIO', WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO],
            ['VIDEO', WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO],
            ['IMAGE', WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE],
        ];
    }

    public static function readLengths(): array
    {
        return array_fill(0, 5,
            [1, 8, 16, 50, 1024, 1024 * 1024]
        );
    }

    public function testEncoderTell(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $coder->read(1000);

        $this->assertEquals(1000, $coder->tell());
    }

    public function testEncoderEof(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );

        $coder->getContents();
        $this->assertEquals(true, $coder->eof());
    }

    public function testEncoderToString(): void
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

        $this->assertEquals($eContent, $coder);
    }

    public function testEncoderGetSize(): void
    {
        $filename = 'AUDIO';
        $mediaType = WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO;
        $stream = new LazyOpenStream(__DIR__ . "/samples/$filename.original", 'r');
        $coder = new WhatsAppEncryptStreamDecorator(
            $stream,
            file_get_contents(__DIR__ . "/samples/$filename.key"),
            $mediaType
        );
        $size = filesize(__DIR__ . "/samples/$filename.encrypted");

        $this->assertEquals($size, $coder->getSize());
    }

    public function testEncoderRewind(): void
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

        $this->assertEquals($eContent, $coder->read(strlen($eContent)));
        $coder->rewind();
        $this->assertEquals($eContent, $coder->read(strlen($eContent)));
    }
}