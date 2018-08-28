# What are these Integration Tests?

These tests supposed to be written and run without any knowledge of the
actual code of cowrie. I wanted to provide some tests, that are meant to
ensure the delivered service is actually running.

## What are these Tests supposed to test?

These tests are supposed to test if anything breaks. This is the reason why
we do not have an explicit input with an assertion of an explicit output.
We just throw commands against the running cowrie service and look if something
breaks.

Small outputs are actually also tested, like log entries when running
commands.

## What are these Tests not supposed to test?

These tests are not supposed to replace unit-tests. So we won't run various
tests against the same command with a predefined input and the assertion of
an expected output. These "how is a command supposed to behave"-tests should
be done in unit-tests.

## Run the tests

Just build it

```bash
docker build -t cowrie/test IntegrationTests/.
```

And run it

```bash
docker run \
    -v $(pwd):/app \
    -v /var/run/docker.sock:/var/run/docker.sock \
    cowrie/test \
        pytest -v IntegrationTests
```
