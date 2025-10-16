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
     * @param StreamInterface $inputStream   Input stream containing data to encrypt.
     * @param string          $encryptionKey Encryption key used for AES encryption and HMAC generation.
     * @param string          $mediaType     Media type (e.g., WhatsAppStreamDecorator::MEDIA_TYPE_IMAGE,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_AUDIO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_VIDEO,
     *                                       WhatsAppStreamDecorator::MEDIA_TYPE_DOCUMENT).
     *
     * @throws WhatsAppDecoratorException If encryption fails.
     */
    public function __construct(
        private readonly StreamInterface $inputStream,
        string $encryptionKey,
        string $mediaType
    ) {
        parent::__construct($this->inputStream, $encryptionKey, $mediaType);

        $this->encodeContent();
    }

    private function encodeContent(): void
    {
        $file = $this->inputStream->getContents();

        $encryptedContent = openssl_encrypt(
            $file,
            'aes-256-cbc',
            $this->cipherKey,
            OPENSSL_RAW_DATA,
            $this->iv
        );

        if ($encryptedContent === false) {
            throw new WhatsAppDecoratorException('Encryption failed.');
        }

        $sign = hash_hmac(
            'sha256',
            $this->iv . $encryptedContent,
            $this->macKey,
            true
        );

        $this->content = $encryptedContent . substr($sign, 0, 10);

        $this->stream = Utils::streamFor($this->content);
    }
}