<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

final class WhatsAppEncryptStreamDecorator extends WhatsAppStreamDecorator
{
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