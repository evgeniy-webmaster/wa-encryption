<?php

declare(strict_types=1);

namespace EW\WaEncryption;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

abstract class WhatsAppStreamDecorator implements StreamInterface
{
    public const MEDIA_TYPE_IMAGE = 'WhatsApp Image Keys';
    public const MEDIA_TYPE_AUDIO = 'WhatsApp Audio Keys';
    public const MEDIA_TYPE_VIDEO = 'WhatsApp Video Keys';
    public const MEDIA_TYPE_DOCUMENT = 'WhatsApp Document Keys';

    use StreamDecoratorTrait;

    protected string $iv;
    protected string $cipherKey;
    protected string $macKey;

    protected string $prevBlock;
    protected string $content;
    protected ?\HashContext $incHashContext;

    protected StreamInterface|null $stream;

    public function __construct(
        private readonly StreamInterface $inputStream,
        private readonly string $encryptionKey,
        string $mediaType
    ) {
        $mediaKeyExpanded = hash_hkdf('sha256', $this->encryptionKey, 112, $mediaType);

        if ($mediaKeyExpanded === false) {
            throw new WhatsAppDecoratorException('hash_hkdf() calculation failed.');
        }

        $this->iv = substr($mediaKeyExpanded, 0, 16);
        $this->cipherKey = substr($mediaKeyExpanded, 16, 48 - 16);
        $this->macKey = substr($mediaKeyExpanded, 48, 80 - 48);
        //$refKey = substr($mediaKeyExpanded, 80);

        $this->prevBlock = $this->iv;
        $this->incHashContext = hash_init('sha256', HASH_HMAC, $this->macKey);
        hash_update($this->incHashContext, $this->iv);
    }
}