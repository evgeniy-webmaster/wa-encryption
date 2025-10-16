## Use 



## Development

Install dependencies for development:

```docker run --rm -it --volume $PWD:/app composer install```

Run tests:

```docker run --rm -v $PWD:/app php:8.4-cli /app/vendor/bin/phpunit /app/tests/```