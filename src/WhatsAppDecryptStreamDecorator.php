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
     * @param StreamInterface $stream   Input stream containing encrypted data.
     * @param string          $encryptionKey Encryption key used for HMAC verification and decryption.
     * @param string          $mediaType     Media type (e.g., WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_DOCUMENT).
     *
     * @throws WhatsAppDecoratorException If signature verification or decryption fails.
     */
    public function __construct(
        private readonly StreamInterface $stream,
        string $encryptionKey,
        string $mediaType
    ) {
        parent::__construct($this->stream, $encryptionKey, $mediaType);
    }

    private string $overBuf = '';
    private int $cSeek = 0; // current seek

    public function eof(): bool
    {
        return $this->stream->eof() && strlen($this->overBuf) === 0;
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new \RuntimeException('Not implemented');
    }

    public function rewind(): void
    {
        $this->stream->rewind();
        $this->prevBlock = $this->iv;
        $this->incHashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->incHashContext, $this->iv);
        $this->cSeek = 0;
    }

    public function read($length): string
    {
        $obLen = strlen($this->overBuf);

        $nLen = 0;
        if ($obLen < $length) {
            $nLen = $length - strlen($this->overBuf);
        }

        $readLength = $nLen + ($nLen % 16 ? 16 - $nLen % 16 : 0);

        $this->cSeek += $readLength;

        if ($this->stream->getSize() - $this->cSeek < 16) {
            $readLength += 11;
        }

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

        for ($i = 0; $i < $readLength; $i += 16) {
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

            if ($this->stream->eof() && $i >= $readLength) {
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

    private function removePkcs7Padding(string $data): string {
        $len = strlen($data);
        $padLen = ord($data[$len - 1]);
        $padding = substr($data, -$padLen);

        if ($padLen >= 1 && $padLen < 16 && $padding === str_repeat(chr($padLen), $padLen)) {
            return substr($data, 0, $len - $padLen);
        }

        return $data;
    }
}