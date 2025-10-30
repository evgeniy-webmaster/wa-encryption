<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * Class WhatsAppDecryptStreamDecorator
 *
 * Decorator for decrypting WhatsApp encrypted data streams.
 * Performs HMAC signature verification and content decryption.
 *
 */
final class WhatsAppDecryptStreamDecorator extends WhatsAppStreamDecorator
{
    /**
     *
     * @param StreamInterface $inputStream   Input stream containing encrypted data.
     * @param string          $encryptionKey Encryption key used for HMAC verification and decryption.
     * @param string          $mediaType     Media type (e.g., WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_DOCUMENT).
     *
     * @throws WhatsAppDecoratorException If signature verification or decryption fails.
     */
    public function __construct(
        private readonly StreamInterface $inputStream,
        string $encryptionKey,
        string $mediaType
    ) {
        parent::__construct($this->inputStream, $encryptionKey, $mediaType);

        $this->stream = $inputStream;

        //$this->decodeContent();
    }

    private string $overBuf = '';

    public function eof(): bool
    {
        return $this->stream->eof() && strlen($this->overBuf) === 0;
    }

    public function read($length): string
    {
        $obLen = strlen($this->overBuf);

        if ($obLen < $length) {
            $nLen = $length - strlen($this->overBuf);
        } else {
            $nLen = $length;
        }

        $nLen = $nLen + ($nLen % 16 ? 16 - $nLen % 16 : 0);
        $readLength = $nLen + 16;

        $inBuf = $this->stream->read($readLength);

        $mac = null;

        if ($this->stream->eof()) {
            $mac = substr($inBuf, -10);
            $inBuf = substr($inBuf, 0, strlen($inBuf) - 10);
            $readLength = strlen($inBuf);
        }

        if ($readLength) {
            hash_update($this->incHashContext, $inBuf);
        }

        $outBuf = '';

        for ($i = 0; $i <= $readLength - 16; $i += 16) {
            $schunk = substr($inBuf, $i, 16);
            $chunk = openssl_decrypt(
                $schunk,
                'aes-256-cbc',
                $this->cipherKey,
                OPENSSL_RAW_DATA |  OPENSSL_ZERO_PADDING,
            );

            if ($chunk === false) {
                throw new WhatsAppDecoratorException('Decryption failed.');
            }

            $chunk = $chunk ^ $this->prevBlock;

            if ($this->stream->eof() && $i >= $readLength - 16) {
                $chunk = $this->removePkcs7Padding($chunk);
            }

            $outBuf .= $chunk;
            $this->prevBlock = $schunk;
        }

        if ($mac) {
            $sign = hash_final($this->incHashContext, true);

            if (!hash_equals(substr($sign, 0, 10), $mac)) {
                throw new WhatsAppDecoratorException('Signature verification failed.');
            }
        }

        $allOutBuf = $this->overBuf . $outBuf;
        $allOutLen = strlen($allOutBuf);

        if ($allOutLen > $length) {
            $this->overBuf = substr($allOutBuf, $length, $allOutLen - $length);
            return substr($allOutBuf, 0, $length);
        }

        $buf = $allOutBuf;
        if ($this->stream->eof()) {
            $buf = $this->removePkcs7Padding($allOutBuf);
        }
        $this->overBuf = '';
        return $buf;
    }

    function removePkcs7Padding(string $data): string {
        $len = strlen($data);
        $padLen = ord($data[$len - 1]);
        $padding = substr($data, -$padLen);

        if ($padLen >= 1 && $padLen < 16 && $padding === str_repeat(chr($padLen), $padLen)) {
            return substr($data, 0, $len - $padLen);
        }

        return $data;
    }

    private function decodeContent(): void
    {
        $content = $this->inputStream->getContents();

        $file = substr($content, 0, strlen($content) - 10);
        $mac = substr($content, -10);

        $sign = hash_hmac(
            'sha256',
            $this->iv . $file,
            $this->macKey,
            true
        );


        if (!hash_equals(substr($sign, 0, 10), $mac)) {
            throw new WhatsAppDecoratorException('Signature verification failed.');
        }

        $decryptedContent = openssl_decrypt(
            $file,
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv,
        );

        if ($decryptedContent === false) {
            throw new WhatsAppDecoratorException('Decryption failed.');
        }

        $this->content = $decryptedContent;

        $this->stream = Utils::streamFor($this->content);
    }
}