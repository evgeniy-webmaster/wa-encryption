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

        $origContent = file_get_contents(__DIR__ . "/samples/$filename.original");
        //$origContent = substr($origContent, 16 * 1005, 16 * 2);
        //$this->assertEquals(substr($decoder->read(8064), 16 * 502, 16 * 5), $origContent);
        //$this->assertEquals($decoder->read(16 * 1007), $origContent);

        //$content = $decoder->getContents();
        //$this->assertEquals($content, $origContent);

        //$decoder->rewind();

        $content = '';
        $i = 0;
        while (!$decoder->eof()) {
            $len = rand(1, 50);
            //$len = 40;
            try {
                //$chunk = $decoder->getContents();
                $chunk = $decoder->read($len);
            } catch (\Throwable $e) {
                var_dump($i);
                throw $e;
            }

            if ($chunk !== substr($origContent, strlen($content), strlen($chunk))) {
                var_dump(bin2hex($chunk));
                var_dump(bin2hex(substr($origContent, strlen($content), $len)));
                var_dump($i);
                die();
            }
            ob_flush();

            $content .= $chunk;
            $i++;
        }

        $this->assertEquals($content, $origContent);
    }

    /**
     * @/dataProvider dataProvider
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
     */

    public static function dataProvider(): array
    {
        return [
            ['AUDIO', WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO],
            //['VIDEO', WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO],
            //['IMAGE', WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE],
        ];
    }
}