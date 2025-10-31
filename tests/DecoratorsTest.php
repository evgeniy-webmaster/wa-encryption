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

        for ($i = 0; $i < 150; ++$i) {
            $content = '';

            while (!$decoder->eof()) {
                $len = $i + 1;
                $chunk = $decoder->read($len);
                $content .= $chunk;
            }

            $this->assertEquals($content, $origContent);
            $decoder->rewind();
        }
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

    public function testEncoderLength(): void
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

        for ($i = 0; $i < 150; ++$i) {
            $content = '';
            $len = $i + 1;

            $j = 0;
            while (!$coder->eof()) {
                $chunk = $coder->read($len);

                /*
                $ch2 = substr($eContent, strlen($content), $len);

                if ($chunk !== $ch2) {
                    var_dump(bin2hex($chunk));
                    var_dump(bin2hex($ch2));
                    var_dump($len);
                    var_dump($j);
                    die();
                }
                */

                $content .= $chunk;
                $j++;
            }

            $this->assertEquals($content, $eContent);
            $coder->rewind();
        }
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