<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

final class WhatsAppDecryptStreamDecorator extends WhatsAppStreamDecorator
{
    public function __construct(
        private readonly StreamInterface $inputStream,
        string $encryptionKey,
        string $mediaType
    ) {
        parent::__construct($this->inputStream, $encryptionKey, $mediaType);

        $this->decodeContent();
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