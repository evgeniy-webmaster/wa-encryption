## How to use 

Add repository to your composer.json:

```
    "repositories": [
        {
            "type": "vcs",
            "url":  "git@github.com:evgeniy-webmaster/wa-encryption.git"
        }
    ]
```

Install package:

```composer require evgeniy-webmaster/wa-encryption:dev-master```

And see usage examples in ./tests/DecoratorsTest.php.

## Development

Install dependencies for development:

```docker run --rm -it --volume $PWD:/app composer install```

Run tests:

```docker run --rm -v $PWD:/app php:8.4-cli /app/vendor/bin/phpunit /app/tests/```

Run psalm:

```docker run -v $PWD:/app --rm -it ghcr.io/danog/psalm:latest /composer/vendor/bin/psalm --no-cache```