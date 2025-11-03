<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

/**
 * Class WhatsAppEncryptStreamDecorator
 *
 * Decorator for encrypting data streams for WhatsApp.
 * Performs content encryption using AES-256-CBC and HMAC signature generation.
 *
 */
final class WhatsAppEncryptStreamDecorator extends WhatsAppStreamDecorator
{
    /**
     *
     * @param StreamInterface $stream   Input stream containing data to encrypt.
     * @param string          $encryptionKey Encryption key used for AES encryption and HMAC generation.
     * @param string          $mediaType     Media type (e.g., WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_DOCUMENT).
     *
     * @throws WhatsAppDecoratorException If encryption fails.
     */
    public function __construct(
        private readonly StreamInterface $stream,
        string $encryptionKey,
        string $mediaType
    ) {
        parent::__construct($this->stream, $encryptionKey, $mediaType);
    }

    private string $overBuf = '';

    /**
     * @inheritDoc
     */
    public function eof(): bool
    {
        return $this->stream->eof() && strlen($this->overBuf) === 0;
    }

    /**
     * @inheritDoc
     */
    public function getSize(): ?int
    {
        $size = $this->stream->getSize();
        $size = $size + ($size % 16 ? 16 - $size % 16 : 0);
        $size += 10;
        return $size;
    }

    /**
     * @inheritDoc
     */
    public function read($length): string
    {
        $obLen = strlen($this->overBuf);

        $nLen = 0;
        if ($obLen < $length) {
            $nLen = $length;
        }

        $readLength = $nLen + ($nLen % 16 ? 16 - $nLen % 16 : 0);

        $inBuf = $this->stream->read($readLength);

        if ($this->stream->eof()) {
            $readLength = strlen($inBuf);
        }

        $outBuf = '';

        for ($i = 0; $i < $readLength; $i += 16) {
            $chunk = substr($inBuf, $i, 16);

            if ($this->stream->eof() && strlen($chunk) < 16) {
                $chunk = $this->addPkcs7Padding($chunk);
            }

            $chunk = openssl_encrypt(
                $chunk,
                'aes-256-cbc',
                $this->cipherKey,
                OPENSSL_RAW_DATA |  OPENSSL_ZERO_PADDING,
                $this->prevBlock
            );

            if ($chunk === false) {
                throw new WhatsAppDecoratorException('Encryption failed.');
            }

            $outBuf .= $chunk;
            $this->prevBlock = $chunk;
        }

        if ($readLength) {
            hash_update($this->incHashContext, $outBuf);
        }

        $allOutBuf = $this->overBuf . $outBuf;

        try {
            if ($this->stream->eof()) {
                $sign = hash_final($this->incHashContext, true);
                $allOutBuf .= substr($sign, 0, 10);
            }
        } catch (\TypeError $e) {}

        $allOutLen = strlen($allOutBuf);

        if ($allOutLen >= $length) {
            $this->overBuf = substr($allOutBuf, $length, $allOutLen - $length);
            return substr($allOutBuf, 0, $length);
        }

        $this->overBuf = '';
        return $allOutBuf;
    }

    private function addPkcs7Padding(string $data): string {
        $dLen = strlen($data);

        if ($dLen >= 1 && $dLen <= 16) {
            $pLen = 16 - $dLen;
            return $data . str_repeat(chr($pLen), $pLen);
        }

        return $data;
    }
}